sap.ui.define([
  "sap/ui/model/json/JSONModel"
], function (JSONModel) {
  "use strict";

  return {
    createSessionModel: function () {
      // Producer cockpit is single-role: auto-authenticated as `producer`
      // (mocked auth). Tracks the busy state for long on-chain actions.
      return new JSONModel({
        user: "producer",
        authenticated: false,
        busy: false,
        walletConnected: false,
        walletToken: "",    // x-wallet-session bearer, minted by walletLogin
        owner: "",          // connected wallet address = passport owner
        ownerVkh: "",
        ownerShort: "",
        passportCount: 0
      });
    }
  };
});
