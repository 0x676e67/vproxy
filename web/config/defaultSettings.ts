import type { ProSettings } from "@ant-design/pro-components";

const settings: Partial<ProSettings> = {
  title: "vproxy",
  navTheme: "realDark",
  colorPrimary: "#1677ff",
  // Keep global account/language actions out of the collapsible navigation rail.
  layout: "mix",
  contentWidth: "Fluid",
  fixedHeader: true,
  fixSiderbar: true,
  splitMenus: false,
};

export default settings;
