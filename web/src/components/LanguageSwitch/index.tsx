import { GlobalOutlined } from "@ant-design/icons";
import { getLocale, setLocale, useIntl } from "@umijs/max";
import { Button, Dropdown } from "antd";
import { useEffect } from "react";

export default function LanguageSwitch() {
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

  return (
    <Dropdown
      trigger={["click"]}
      autoFocus
      menu={{
        "aria-label": label,
        items: languages,
        selectable: true,
        selectedKeys: [locale],
        onClick: ({ key }) => {
          // Umi persists the preference; no reload means local forms stay intact.
          setLocale(key, false);
        },
      }}
    >
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
