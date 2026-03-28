import { StyleSheet } from "react-native";

export const INPUT_BG = "#1e1e1e";
export const INPUT_TEXT = "#f0f0f0";
export const INPUT_PLACEHOLDER = "#777";
export const INPUT_BORDER = "#3a3a3a";
export const INPUT_BORDER_FOCUS = "#4a90d9";
export const INPUT_BORDER_ERROR = "#ef4444";
export const INPUT_BORDER_SUCCESS = "#4CAF50";
export const LABEL_COLOR = "#999";

export const inputStyles = StyleSheet.create({
  input: {
    color: INPUT_TEXT,
    fontSize: 16,
    backgroundColor: INPUT_BG,
    borderRadius: 8,
    padding: 12,
    borderWidth: 1,
    borderColor: INPUT_BORDER,
  },
  inputLarge: {
    color: INPUT_TEXT,
    fontSize: 18,
    backgroundColor: INPUT_BG,
    borderRadius: 8,
    padding: 16,
    borderWidth: 1,
    borderColor: INPUT_BORDER,
  },
  label: {
    color: LABEL_COLOR,
    fontSize: 12,
    marginBottom: 6,
    textTransform: "uppercase" as const,
  },
});
