import { createRequire } from "node:module";
import { defineConfig } from "hardhat/config";
import hardhatEthers from "@nomicfoundation/hardhat-ethers";
import hardhatEthersChaiMatchers from "@nomicfoundation/hardhat-ethers-chai-matchers";
import hardhatMocha from "@nomicfoundation/hardhat-mocha";
import hardhatNetworkHelpers from "@nomicfoundation/hardhat-network-helpers";
import hardhatTypechain from "@nomicfoundation/hardhat-typechain";

const require = createRequire(import.meta.url);

// The compiler is the pinned `solc` npm package (solc-js, 0.8.38). Pointing `path` at its
// soljson.js means Hardhat never downloads a compiler binary; the file comes from the
// lockfile-verified npm tarball.
const SOLC_VERSION = "0.8.38";
const solcJsPath = require.resolve("solc/soljson.js");

export default defineConfig({
  plugins: [hardhatEthers, hardhatEthersChaiMatchers, hardhatMocha, hardhatNetworkHelpers, hardhatTypechain],
  solidity: {
    version: SOLC_VERSION,
    path: solcJsPath,
    settings: {
      evmVersion: "cancun",
      optimizer: { enabled: true, runs: 200 },
    },
  },
  networks: {
    // The in-process simulated network. No node, no RPC, no funds.
    hardhat: {
      type: "edr-simulated",
      chainType: "l1",
      hardfork: "cancun",
      chainId: 31337,
    },
  },
  test: {
    mocha: {
      timeout: 60_000,
    },
  },
});
