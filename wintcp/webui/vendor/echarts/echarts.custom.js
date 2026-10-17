// ECharts custom bundle wrapper
// The full ECharts build is 1MB which exceeds the 1 MiB static asset cap.
// Per the brief, we raise the cap for /vendor/ only and document why.
// A tree-shaken custom build (target < 450 KB) would replace this.
import echarts from "./echarts.min.js";
export default echarts;
