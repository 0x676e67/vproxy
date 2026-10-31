import { GlobalOutlined } from "@ant-design/icons";
import { getLocale, setLocale, useIntl } from "@umijs/max";
import { Button, Dropdown, type MenuProps } from "antd";
import { useEffect } from "react";

/** Locale changes stay in place so an open configuration draft is retained. */
export function useLanguageMenu() {
  const intl = useIntl();
  const locale = getLocale();
  const languages = [
    { key: "zh-CN", label: "简体中文" },
    { key: "en-US", label: "English" },
  ];
  const label = intl.formatMessage({ id: "app.language" });
  const currentLanguage = languages.find(({ key }) => key === locale)?.label;
  const triggerLabel = `${label}: ${currentLanguage ?? locale}`;

  useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);

  return {
    locale,
    label,
    triggerLabel,
    menu: {
      "aria-label": label,
      items: languages,
      selectable: true,
      selectedKeys: [locale],
      onClick: ({ key }) => {
        if (key === "zh-CN" || key === "en-US") setLocale(key, false);
      },
    } satisfies MenuProps,
  };
}

export default function LanguageSwitch() {
  const { triggerLabel, menu } = useLanguageMenu();
  return (
    <Dropdown trigger={["click"]} autoFocus menu={menu}>
      <Button
        className="management-header-action management-language"
        type="text"
        icon={<GlobalOutlined aria-hidden />}
        aria-label={triggerLabel}
        aria-haspopup="menu"
        title={triggerLabel}
      />
    </Dropdown>
  );
}
