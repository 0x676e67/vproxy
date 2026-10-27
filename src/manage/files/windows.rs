//! Audited Windows boundary for newly created private application files.
//!
//! Directories receive a protected DACL at creation, granting only the current
//! process user and SYSTEM. New files receive their own protected DACL. Nothing
//! changes an existing object's ACL. Reads audit the opened handle, not a second
//! path lookup; reparse points, non-disk objects and multiply linked private
//! files are rejected. Ancestors remain trusted and hostile same-user mutation
//! is outside this boundary. Administrators/SYSTEM can still take ownership.
//!
//! Every owned HANDLE becomes a standard RAII owner once. LocalAlloc results
//! returned by the security APIs are freed only by LocalFree. Token buffers are
//! word-aligned, length-bounded and remain alive while their SID is borrowed.
//! Descriptor/ACL/ACE/SID offsets are checked before dereferencing variable-size
//! records. All paths are bounded, NUL-terminated UTF-16 without interior NULs.

// The crate continues to deny unsafe elsewhere. Windows has no std API for
// atomically creating a protected DACL or auditing SID/ACE data by handle.
#![allow(unsafe_code)]

use std::{
    ffi::c_void,
    fs::File,
    io,
    mem::{offset_of, size_of},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    ptr::{self, NonNull},
    slice,
};

use windows_sys::Win32::{
    Foundation::{
        ERROR_INSUFFICIENT_BUFFER, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, LocalFree,
    },
    Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
        },
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
        GetSecurityDescriptorControl, GetSecurityDescriptorLength, GetTokenInformation,
        INHERIT_ONLY_ACE, IsValidAcl, IsValidSecurityDescriptor, IsValidSid, IsWellKnownSid,
        OWNER_SECURITY_INFORMATION, PSID, SE_DACL_PRESENT, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER, TokenUser, WinLocalSystemSid,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK, GetFileInformationByHandle, GetFileType,
        OPEN_EXISTING, READ_CONTROL,
    },
    System::{
        SystemServices::ACCESS_ALLOWED_ACE_TYPE,
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

const MAX_PATH_UNITS: usize = 32_767;
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_DESCRIPTOR_BYTES: usize = 1024 * 1024;
const MAX_ACES: u32 = 64;
const MAX_SID_STRING_UNITS: usize = 184;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

struct LocalMemory(NonNull<c_void>);

impl LocalMemory {
    fn new(pointer: *mut c_void) -> io::Result<Self> {
        NonNull::new(pointer)
            .map(Self)
            .ok_or_else(|| invalid("Windows returned an empty setup security allocation"))
    }

    fn pointer(&self) -> *mut c_void {
        self.0.as_ptr()
    }
}

impl Drop for LocalMemory {
    fn drop(&mut self) {
        // SAFETY: only successful LocalAlloc-returning APIs construct this
        // owner; it is neither cloned nor exposed for independent freeing.
        unsafe {
            LocalFree(self.pointer());
        }
    }
}

struct User {
    storage: Vec<usize>,
    sid_offset: usize,
}

impl User {
    fn current() -> io::Result<Self> {
        let mut handle = ptr::null_mut();
        // SAFETY: the pseudo process handle is borrowed; the output points to
        // a live HANDLE slot. Only TOKEN_QUERY is requested.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(invalid("Windows returned an invalid setup token handle"));
        }
        // SAFETY: OpenProcessToken succeeded and transfers exactly one handle.
        let token = unsafe { OwnedHandle::from_raw_handle(handle) };
        let mut required = 0_u32;
        // SAFETY: a null buffer with length zero queries the required size.
        let result = unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                ptr::null_mut(),
                0,
                &mut required,
            )
        };
        if result != 0
            || io::Error::last_os_error().raw_os_error()
                != i32::try_from(ERROR_INSUFFICIENT_BUFFER).ok()
        {
            return Err(invalid("cannot size the current Windows setup user"));
        }
        let required_usize = usize::try_from(required)
            .map_err(|_| invalid("Windows setup token size exceeds its limit"))?;
        if !(size_of::<TOKEN_USER>()..=MAX_TOKEN_BYTES).contains(&required_usize) {
            return Err(invalid("Windows setup token size exceeds its limit"));
        }
        let words = required_usize
            .checked_add(size_of::<usize>() - 1)
            .ok_or_else(|| invalid("Windows setup token size overflow"))?
            / size_of::<usize>();
        let mut storage = vec![0_usize; words];
        let mut returned = required;
        // SAFETY: the word-aligned allocation has at least `required` bytes;
        // its capacity/lifetime are unchanged until the SID has been checked.
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                storage.as_mut_ptr().cast(),
                required,
                &mut returned,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let returned =
            usize::try_from(returned).map_err(|_| invalid("invalid Windows setup token size"))?;
        if returned < size_of::<TOKEN_USER>() || returned > required_usize {
            return Err(invalid("invalid Windows setup token size"));
        }
        // SAFETY: TOKEN_USER fits and is aligned in the successful API output.
        let user = unsafe { ptr::read(storage.as_ptr().cast::<TOKEN_USER>()) };
        let start = storage.as_ptr() as usize;
        let sid_offset = (user.User.Sid as usize)
            .checked_sub(start)
            .filter(|offset| *offset < returned)
            .ok_or_else(|| invalid("Windows setup token SID is out of bounds"))?;
        // SAFETY: the SID pointer is within the still-live token allocation;
        // checked_sid verifies its variable-length encoding fits the remainder.
        unsafe {
            checked_sid(user.User.Sid, returned - sid_offset)?;
        }
        Ok(Self {
            storage,
            sid_offset,
        })
    }

    fn sid(&self) -> PSID {
        self.storage
            .as_ptr()
            .cast::<u8>()
            .wrapping_add(self.sid_offset)
            .cast_mut()
            .cast()
    }

    fn sid_string(&self) -> io::Result<String> {
        let mut pointer = ptr::null_mut();
        // SAFETY: this validated SID remains owned by self through conversion.
        if unsafe { ConvertSidToStringSidW(self.sid(), &mut pointer) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let allocation = LocalMemory::new(pointer.cast())?;
        for length in 0..MAX_SID_STRING_UNITS {
            // SAFETY: this API guarantees a NUL-terminated SID string; a valid
            // SID's textual representation fits the documented bound above.
            if unsafe { *pointer.add(length) } == 0 {
                // SAFETY: the prefix lies before that live allocation's NUL.
                let units = unsafe { slice::from_raw_parts(pointer, length) };
                let value = String::from_utf16(units)
                    .map_err(|_| invalid("Windows returned an invalid setup user SID"))?;
                drop(allocation);
                return Ok(value);
            }
        }
        Err(invalid("Windows setup user SID exceeds its limit"))
    }
}

struct Descriptor(LocalMemory);

impl Descriptor {
    fn private(directory: bool) -> io::Result<Self> {
        let user = User::current()?.sid_string()?;
        let inherit = if directory { "OICI" } else { "" };
        // Pin ownership too: an elevated token's default owner can otherwise
        // be Administrators even though its user SID is the intended owner.
        Self::from_sddl(&format!(
            "O:{user}D:P(A;{inherit};FA;;;{user})(A;{inherit};FA;;;SY)"
        ))
    }

    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let units: Vec<_> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut pointer = ptr::null_mut();
        // SAFETY: this internally constructed SDDL is NUL-terminated and lives
        // through the call. The returned self-relative descriptor uses LocalFree.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                units.as_ptr(),
                SDDL_REVISION_1,
                &mut pointer,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(LocalMemory::new(pointer)?))
    }

    fn attributes(&self) -> io::Result<SECURITY_ATTRIBUTES> {
        Ok(SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
                .map_err(|_| invalid("Windows setup security attributes size overflow"))?,
            lpSecurityDescriptor: self.0.pointer(),
            bInheritHandle: 0,
        })
    }
}

pub(super) fn create_directory(path: &Path) -> io::Result<()> {
    let path_units = wide_path(path)?;
    let descriptor = Descriptor::private(true)?;
    let attributes = descriptor.attributes()?;
    // SAFETY: path and descriptor owners outlive the call. CreateDirectoryW
    // applies this protected DACL atomically and refuses any existing leaf.
    if unsafe { CreateDirectoryW(path_units.as_ptr(), &attributes) } == 0 {
        return Err(io::Error::last_os_error());
    }
    check_directory(path, true)
}

pub(super) fn create_file(path: &Path) -> io::Result<File> {
    create_with_sharing(path, false)
}

/// Claim a private SQLite destination without preventing its second writable
/// connection. The caller retains this owner through SQLite close and fsync;
/// delete/rename sharing remains disabled. This does not serialize SQL writers.
#[cfg(feature = "management")]
pub(super) fn create_database(path: &Path) -> io::Result<File> {
    create_with_sharing(path, true)
}

fn create_with_sharing(path: &Path, share_write: bool) -> io::Result<File> {
    let descriptor = Descriptor::private(false)?;
    let file = new_file(path, &descriptor, share_write)?;
    inspect(&file, false, true)?;
    audit(&file, true)?;
    Ok(file)
}

fn new_file(path: &Path, descriptor: &Descriptor, share_write: bool) -> io::Result<File> {
    let units = wide_path(path)?;
    let attributes = descriptor.attributes()?;
    // SAFETY: all input pointers stay live through the call. CREATE_NEW never
    // replaces an existing object; OPEN_REPARSE_POINT never follows its leaf.
    let handle = unsafe {
        CreateFileW(
            units.as_ptr(),
            GENERIC_WRITE | READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | if share_write { FILE_SHARE_WRITE } else { 0 },
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    file_owner(handle)
}

pub(super) fn open_file(path: &Path, private: bool) -> io::Result<File> {
    read_file(path, private, false)
}

/// Read and audit a private input without excluding an existing SQLite writer.
/// Sharing grants no filesystem permissions and allows neither deletion nor
/// replacement. It is not an immutable snapshot; callers retain SQL gates and
/// verify the copied database/manifest instead of relying on a read handle lock.
#[cfg(feature = "management")]
pub(super) fn open_shared_file(path: &Path) -> io::Result<File> {
    read_file(path, true, true)
}

fn read_file(path: &Path, private: bool, share_write: bool) -> io::Result<File> {
    let file = open_with_sharing(path, GENERIC_READ | READ_CONTROL, false, share_write)?;
    inspect(&file, false, private)?;
    if private {
        audit(&file, false)?;
    }
    Ok(file)
}

pub(super) fn check_directory(path: &Path, private: bool) -> io::Result<()> {
    let file = open(path, READ_CONTROL | FILE_READ_ATTRIBUTES, true)?;
    inspect(&file, true, false)?;
    if private {
        audit(&file, true)?;
    }
    Ok(())
}

fn open(path: &Path, access: u32, directory: bool) -> io::Result<File> {
    open_with_sharing(path, access, directory, false)
}

fn open_with_sharing(
    path: &Path,
    access: u32,
    directory: bool,
    share_write: bool,
) -> io::Result<File> {
    let units = wide_path(path)?;
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            0
        };
    // SAFETY: the path is a live, terminated UTF-16 string. Ordinary inputs share
    // reads only; SQLite inspection also permits its cooperating writable handle.
    // Neither mode shares delete access or freezes ACLs against the same user.
    let handle = unsafe {
        CreateFileW(
            units.as_ptr(),
            access,
            FILE_SHARE_READ | if share_write { FILE_SHARE_WRITE } else { 0 },
            ptr::null(),
            OPEN_EXISTING,
            flags,
            ptr::null_mut(),
        )
    };
    file_owner(handle)
}

fn file_owner(handle: *mut c_void) -> io::Result<File> {
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    if handle.is_null() {
        return Err(invalid("Windows returned an empty setup file handle"));
    }
    // SAFETY: only a successful CreateFileW result reaches this function; the
    // returned File owns its one CloseHandle responsibility from this point.
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn inspect(file: &File, directory: bool, single_link: bool) -> io::Result<()> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: File owns the open handle and the output structure is initialized.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the handle stays open for this non-owning query.
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
    {
        return Err(invalid(
            "setup object must be a regular non-reparse disk object",
        ));
    }
    if single_link && information.nNumberOfLinks != 1 {
        return Err(denied("setup private file must have exactly one link"));
    }
    Ok(())
}

fn audit(file: &File, protected: bool) -> io::Result<()> {
    let user = User::current()?;
    let mut owner = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: all output slots are live. On success their pointers borrow the
    // returned LocalAlloc descriptor until its single owner is dropped below.
    let error = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if error != 0 {
        return Err(denied("cannot inspect Windows setup file security"));
    }
    let allocation = LocalMemory::new(descriptor)?;
    // SAFETY: GetSecurityInfo returned a live, OS-owned security descriptor.
    if unsafe { IsValidSecurityDescriptor(descriptor) } == 0 {
        return Err(denied("Windows setup security descriptor is invalid"));
    }
    // SAFETY: validation succeeded and the allocation is still alive.
    let length = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
    if length == 0 || length > MAX_DESCRIPTOR_BYTES {
        return Err(denied(
            "Windows setup security descriptor exceeds its limit",
        ));
    }
    let owner_available = remainder(descriptor, length, owner)
        .ok_or_else(|| denied("Windows setup owner SID is out of bounds"))?;
    // SAFETY: owner is inside the descriptor; the helper bounds its full SID.
    unsafe {
        checked_sid(owner, owner_available)?;
    }
    // SAFETY: both SIDs were validated and their owners remain alive.
    if unsafe { EqualSid(owner, user.sid()) } == 0
        && unsafe { IsWellKnownSid(owner, WinLocalSystemSid) } == 0
    {
        return Err(denied("Windows setup object has an unexpected owner"));
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: the descriptor and both output slots remain valid.
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(denied("cannot inspect Windows setup DACL control"));
    }
    if control & SE_DACL_PRESENT == 0 || (protected && control & SE_DACL_PROTECTED == 0) {
        return Err(denied(
            "Windows setup object requires a protected private DACL",
        ));
    }
    let acl_available = remainder(descriptor, length, dacl.cast())
        .filter(|available| *available >= size_of::<ACL>())
        .ok_or_else(|| denied("Windows setup DACL is absent or out of bounds"))?;
    // SAFETY: the fixed ACL header fits the live descriptor allocation.
    let acl = unsafe { ptr::read_unaligned(dacl) };
    let acl_length = usize::from(acl.AclSize);
    if acl_length < size_of::<ACL>() || acl_length > acl_available {
        return Err(denied("Windows setup DACL length is invalid"));
    }
    // SAFETY: its complete declared size fits the descriptor.
    if unsafe { IsValidAcl(dacl) } == 0 {
        return Err(denied("Windows setup DACL is invalid"));
    }
    let mut information = ACL_SIZE_INFORMATION::default();
    let information_size = u32::try_from(size_of::<ACL_SIZE_INFORMATION>())
        .map_err(|_| invalid("Windows setup ACL information size overflow"))?;
    // SAFETY: the ACL was validated and the correctly sized output stays live.
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
            information_size,
            AclSizeInformation,
        )
    } == 0
        || information.AceCount == 0
        || information.AceCount > MAX_ACES
    {
        return Err(denied("Windows setup DACL entries exceed their limits"));
    }
    let mut user_access = false;
    for index in 0..information.AceCount {
        let mut entry = ptr::null_mut();
        // SAFETY: index is inside the validated ACL's reported ACE count.
        if unsafe { GetAce(dacl, index, &mut entry) } == 0 {
            return Err(denied("cannot inspect a Windows setup DACL entry"));
        }
        let available = remainder(dacl.cast(), acl_length, entry)
            .filter(|available| *available >= size_of::<ACE_HEADER>())
            .ok_or_else(|| denied("Windows setup DACL entry is out of bounds"))?;
        // SAFETY: the fixed header fits the validated ACL allocation.
        let header = unsafe { ptr::read_unaligned(entry.cast::<ACE_HEADER>()) };
        let entry_length = usize::from(header.AceSize);
        let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
            || entry_length > available
            || entry_length < sid_offset
        {
            return Err(denied(
                "Windows setup DACL requires ordinary private allow entries",
            ));
        }
        // SAFETY: sid_offset is within this ACE; checked_sid checks the entire
        // variable-length SID before either Windows SID-comparison function.
        let sid = unsafe { entry.cast::<u8>().add(sid_offset).cast::<c_void>() };
        unsafe {
            checked_sid(sid, entry_length - sid_offset)?;
        }
        // SAFETY: both SIDs have bounded validated encodings and live owners.
        let is_user = unsafe { EqualSid(sid, user.sid()) } != 0;
        if !is_user && unsafe { IsWellKnownSid(sid, WinLocalSystemSid) } == 0 {
            return Err(denied(
                "Windows setup DACL grants access to another identity",
            ));
        }
        // SAFETY: an ordinary allow ACE with a bounded SID has its fixed Mask
        // field before SidStart, and that full prefix has already been checked.
        let mask = unsafe {
            ptr::read_unaligned(
                entry
                    .cast::<u8>()
                    .add(offset_of!(ACCESS_ALLOWED_ACE, Mask))
                    .cast::<u32>(),
            )
        };
        user_access |= is_user && u32::from(header.AceFlags) & INHERIT_ONLY_ACE == 0 && mask != 0;
    }
    if !user_access {
        return Err(denied(
            "Windows setup DACL does not grant current-user access",
        ));
    }
    drop(allocation);
    Ok(())
}

fn remainder(base: *mut c_void, length: usize, pointer: *mut c_void) -> Option<usize> {
    if pointer.is_null() {
        return None;
    }
    let offset = (pointer as usize).checked_sub(base as usize)?;
    length.checked_sub(offset)
}

/// # Safety
/// `sid` points into a live allocation with at least `available` bytes. The
/// caller retains that allocation throughout this function and all later use.
unsafe fn checked_sid(sid: PSID, available: usize) -> io::Result<()> {
    if sid.is_null() || available < 8 {
        return Err(denied("Windows setup SID is missing or truncated"));
    }
    // SAFETY: the caller guarantees the allocation; the fixed SID prefix fits.
    let prefix = unsafe { slice::from_raw_parts(sid.cast::<u8>(), 8) };
    let length = usize::from(prefix[1])
        .checked_mul(4)
        .and_then(|subauthorities| subauthorities.checked_add(8))
        .filter(|length| *length <= available)
        .ok_or_else(|| denied("Windows setup SID length is invalid"))?;
    // SAFETY: the SID's full variable-size encoding fits this live allocation.
    if length < 8 || unsafe { IsValidSid(sid) } == 0 {
        return Err(denied("Windows setup SID is invalid"));
    }
    Ok(())
}

fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    let mut units: Vec<_> = path
        .as_os_str()
        .encode_wide()
        .take(MAX_PATH_UNITS)
        .collect();
    if units.is_empty() || units.len() >= MAX_PATH_UNITS || units.contains(&0) {
        return Err(invalid(
            "Windows setup path is empty, excessive or contains NUL",
        ));
    }
    units.push(0);
    Ok(units)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, io::Write};

    #[test]
    fn protected_child_excludes_everyone_inheritance_from_owned_parent() -> io::Result<()> {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| io::Error::other("test entropy unavailable"))?;
        let parent = std::env::temp_dir().join(format!(
            "vproxy-setup-parent-{:032x}",
            u128::from_ne_bytes(random)
        ));
        let user = User::current()?.sid_string()?;
        let descriptor = Descriptor::from_sddl(&format!(
            "O:{user}D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)(A;OICI;FR;;;WD)"
        ))?;
        let path = wide_path(&parent)?;
        let attributes = descriptor.attributes()?;
        // SAFETY: this exclusively created fixture path and descriptor are
        // live for the call; no existing object's permissions are changed.
        if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } == 0 {
            return Err(io::Error::last_os_error());
        }
        assert!(check_directory(&parent, true).is_err());
        let child = parent.join("private");
        create_directory(&child)?;
        check_directory(&child, true)?;
        let key = child.join("key.pem");
        drop(create_file(&key)?);
        drop(open_file(&key, true)?);
        fs::remove_file(key)?;
        fs::remove_dir(child)?;
        fs::remove_dir(parent)?;
        Ok(())
    }

    #[test]
    fn protected_outputs_are_private_and_loose_file_dacls_are_rejected() -> io::Result<()> {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| io::Error::other("test entropy unavailable"))?;
        let path = std::env::temp_dir().join(format!(
            "vproxy-setup-acl-{:032x}",
            u128::from_ne_bytes(random)
        ));
        create_directory(&path)?;
        check_directory(&path, true)?;
        let key = path.join("key.pem");
        let mut file = create_file(&key)?;
        file.write_all(b"private")?;
        file.sync_all()?;
        drop(file);
        assert!(open_file(&key, true).is_ok());
        let alias = path.join("alias.pem");
        fs::hard_link(&key, &alias)?;
        assert!(open_file(&key, true).is_err());
        #[cfg(feature = "management")]
        assert!(open_shared_file(&key).is_err());
        fs::remove_file(alias)?;
        let user = User::current()?.sid_string()?;
        let loose = Descriptor::from_sddl(&format!(
            "O:{user}D:P(A;;FA;;;{user})(A;;FA;;;SY)(A;;FR;;;WD)"
        ))?;
        let public = path.join("public.pem");
        let mut file = new_file(&public, &loose, false)?;
        file.write_all(b"public")?;
        file.sync_all()?;
        drop(file);
        assert!(open_file(&public, true).is_err());
        #[cfg(feature = "management")]
        assert!(open_shared_file(&public).is_err());
        assert!(open_file(&public, false).is_ok());
        assert!(open_file(&path, false).is_err());
        let child = path.join("child");
        create_directory(&child)?;
        let link = path.join("redirect");
        match std::os::windows::fs::symlink_dir(&child, &link) {
            Ok(()) => {
                assert!(check_directory(&link, false).is_err());
                fs::remove_dir(link)?;
            }
            // Developer mode/symlink privilege is not present on every runner.
            Err(error) if error.raw_os_error() == Some(1314) => {}
            Err(error) => return Err(error),
        }
        fs::remove_dir(child)?;
        fs::remove_file(public)?;
        fs::remove_file(key)?;
        fs::remove_dir(path)?;
        Ok(())
    }
}
