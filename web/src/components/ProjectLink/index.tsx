import { GithubOutlined } from "@ant-design/icons";
import { useMessages } from "../../hooks/useMessages";

export default function ProjectLink() {
  const { t } = useMessages();
  const label = t("app.projectRepository");
  return (
    <a
      className="management-header-action"
      href="https://github.com/0x676e67/vproxy"
      target="_blank"
      rel="noopener noreferrer"
      aria-label={label}
      title={label}
    >
      <span className="management-header-icon">
        <GithubOutlined aria-hidden />
      </span>
    </a>
  );
}
