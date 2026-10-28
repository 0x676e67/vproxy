import type { ProSettings } from "@ant-design/pro-components";
import { consolePalette } from "./theme";

const settings: Partial<ProSettings> = {
  title: "vproxy",
  navTheme: "light",
  colorPrimary: consolePalette.accent,
  // Keep global account/language actions out of the collapsible navigation rail.
  layout: "mix",
  contentWidth: "Fluid",
  fixedHeader: true,
  fixSiderbar: true,
  splitMenus: false,
};

export default settings;
