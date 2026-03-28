const { getDefaultConfig } = require("expo/metro-config");

const config = getDefaultConfig(__dirname);

config.transformer = {
  ...config.transformer,
  minifierPath: "metro-minify-terser",
  minifierConfig: {
    compress: {
      drop_console: true,
      drop_debugger: true,
      passes: 2,
      dead_code: true,
      conditionals: true,
      evaluate: true,
    },
    mangle: {
      toplevel: true,
      reserved: [
        "HomeScreen",
        "VaultScreen",
        "AuthScreen",
        "SeedSetupScreen",
      ],
    },
    output: {
      comments: false,
      ascii_only: true,
    },
  },
};

module.exports = config;
