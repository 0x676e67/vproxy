import { DownOutlined } from "@ant-design/icons";
import { Link } from "@umijs/max";
import { Button, Dropdown, Space } from "antd";
import { useEffect, useRef, useState } from "react";
import type { ProxyUser } from "../../api/proxy";
import { trafficHref } from "../../api/traffic";
import { useMessages } from "../../hooks/useMessages";

export type UserAction =
  "credentials" | "routing" | "preset" | "edit" | "state" | "delete";

/** Editors return focus to the persistent row trigger, never a removed menu item. */
export default function UserActions({
  user,
  targetId,
  readDisabled,
  writeDisabled,
  onAction,
}: {
  user: ProxyUser;
  targetId: string | null;
  readDisabled: boolean;
  writeDisabled: boolean;
  onAction: (action: UserAction, trigger: HTMLElement) => void;
}) {
  const { t } = useMessages();
  const trigger = useRef<HTMLButtonElement>(null);
  const [open, setOpen] = useState(false);
  useEffect(() => {
    // Finishing a read must not reopen a menu over the next task's dialog.
    if (readDisabled) setOpen(false);
  }, [readDisabled]);
  const cannotWrite = writeDisabled || user.deleted;
  return (
    <Space wrap>
      <Button
        size="small"
        type="primary"
        disabled={readDisabled}
        onClick={(event) => onAction("credentials", event.currentTarget)}
      >
        {t("users.credentials")}
      </Button>
      <Link to={trafficHref({ kind: "user", id: user.id }, targetId)}>
        {t("traffic.open")}
      </Link>
      <Dropdown
        trigger={["click"]}
        open={open && !readDisabled}
        onOpenChange={setOpen}
        menu={{
          items: [
            {
              key: "routing",
              label: t("resources.permission"),
              disabled: readDisabled,
            },
            {
              key: "preset",
              label: t("presets.title"),
              disabled: readDisabled,
            },
            { key: "edit", label: t("users.edit"), disabled: cannotWrite },
            { type: "divider" },
            {
              key: "state",
              label: t(user.active ? "users.disable" : "users.enable"),
              danger: user.active,
              disabled: cannotWrite,
            },
            {
              key: "delete",
              label: t("users.delete"),
              danger: true,
              disabled: cannotWrite,
            },
          ],
          onClick: ({ key, domEvent }) => {
            // Enter must not activate the dialog's newly focused close button.
            if ("key" in domEvent) domEvent.preventDefault();
            setOpen(false);
            if (!trigger.current || readDisabled) return;
            if (key === "routing" || key === "preset")
              onAction(key, trigger.current);
            else if (
              !cannotWrite &&
              (key === "edit" || key === "state" || key === "delete")
            )
              onAction(key, trigger.current);
          },
        }}
      >
        <Button
          ref={trigger}
          size="small"
          disabled={readDisabled}
          aria-haspopup="menu"
          aria-expanded={open && !readDisabled}
        >
          {t("users.moreActions")} <DownOutlined aria-hidden />
        </Button>
      </Dropdown>
    </Space>
  );
}
