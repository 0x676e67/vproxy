import type { ProSettings } from "@ant-design/pro-components";
import { consolePalette } from "./theme";

const settings: Partial<ProSettings> = {
  title: "vproxy",
  navTheme: "light",
  colorPrimary: consolePalette.accent,
  // This ProLayout version omits the desktop header in `side` mode.
  // Retain its header and drawer; the shell aligns them with the full-height rail.
  layout: "mix",
  contentWidth: "Fluid",
  fixedHeader: true,
  fixSiderbar: true,
  splitMenus: false,
};

export default settings;
