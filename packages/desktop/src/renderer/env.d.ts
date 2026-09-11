interface Window {
  osecDesktop?: import("@0sec/shared").DesktopHostBridge;
}

declare module "*.svg" {
  const url: string;
  export default url;
}
declare module "*.css";
