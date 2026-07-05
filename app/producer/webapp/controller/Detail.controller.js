sap.ui.define([
  "producer/controller/BaseController",
  "sap/ui/model/Filter",
  "sap/ui/model/FilterOperator",
  "sap/ui/model/Sorter",
  "sap/ui/core/Fragment",
  "sap/ui/model/json/JSONModel",
  "sap/m/MessageBox",
  "producer/lib/cardano-wallet"
], function (BaseController, Filter, FilterOperator, Sorter, Fragment, JSONModel, MessageBox, wallet) {
  "use strict";

  return BaseController.extend("producer.controller.Detail", {

    onInit: function () {
      this._router().getRoute("detail").attachPatternMatched(this._onMatched, this);
      this.getView().setModel(new JSONModel({ anchored: false }), "ui");
      this.getView().setModel(new JSONModel({ aspect: "", pac: "" }), "cx");
      // Field disclosure (Track A) result.
      this.getView().setModel(new JSONModel({ value: "", scaledValue: "", contentRoot: "", json: "" }), "disc");
    },

    // Every chain action signs in the connected CIP-30 wallet.
    onAttest: function () {
      return this.getView().getModel("ui").getProperty("/anchored")
        ? this.onReattestWithWallet() : this.onAttestWithWallet();
    },
    onGrantAction:  function () { return this.onGrantWithWallet("grant"); },
    onRevokeAction: function () { return this.onGrantWithWallet("revoke"); },
    // Track A disclosure never submits a tx.
    onDiscloseAction: function () { return this.onDisclose(); },

    _onMatched: function (oEvent) {
      var sKey = decodeURIComponent(oEvent.getParameter("arguments").key);
      this._key = sKey;
      this._id = sKey.replace(/^ID=/, "").replace(/^'|'$/g, "");
      this.getView().bindElement({
        path: "/Passports(" + sKey + ")",
        parameters: { $expand: "batteries" },
        events: { dataReceived: this._syncAnchored.bind(this) }
      });
      this._filterLogs(this._id);
      this._syncAnchored();
    },

    _syncAnchored: function () {
      var oCtx = this.getView().getBindingContext();
      var oUi = this.getView().getModel("ui");
      if (!oCtx) { oUi.setProperty("/anchored", false); return; }
      oCtx.requestProperty("status").then(function (s) {
        oUi.setProperty("/anchored", s === "anchored");
      }).catch(function () { oUi.setProperty("/anchored", false); });
    },

    _filterLogs: function (sKey) {
      var oFilter = new Filter("passport_ID", FilterOperator.EQ, sKey);
      var oSorter = new Sorter("createdAt", true);
      ["txTable", "discTable", "proofTable"].forEach(function (sId) {
        var oCtrl = this.byId(sId);
        var oBinding = oCtrl && oCtrl.getBinding("items");
        if (oBinding) { oBinding.filter(oFilter); oBinding.sort(oSorter); }
      }.bind(this));
    },

    _refreshAll: function () {
      var oCtx = this.getView().getBindingContext();
      if (oCtx) { oCtx.refresh(); }
      ["txTable", "discTable", "proofTable"].forEach(function (sId) {
        var oBinding = this.byId(sId) && this.byId(sId).getBinding("items");
        if (oBinding) { oBinding.refresh(); }
      }.bind(this));
      this._syncAnchored();
    },

    _pid: function () {
      var oCtx = this.getView().getBindingContext();
      return oCtx ? oCtx.getProperty("passportId") : null;
    },

    onNavBack: function () {
      this._router().navTo("main");
    },

    onRefresh: function () {
      this._refreshAll();
    },

    // ---- Catena-X: aspect JSON + PAC ----------------------------------------
    _cx: function () { return this.getView().getModel("cx"); },
    _unwrap: function (res) { return (res && (res.value != null ? res.value : res)) || ""; },

    onGenerateAspect: function () {
      var that = this;
      this.callAction("/passportAspectJson", { passportId: this._pid() })
        .then(function (res) { that._cx().setProperty("/aspect", that._unwrap(res)); })
        .catch(function (e) { that.error(e); });
    },

    onBuildPac: function () {
      var that = this;
      this.callAction("/passportCredential", { passportId: this._pid() })
        .then(function (res) {
          var pac = that._unwrap(res);
          that._cx().setProperty("/pac", pac);
          try {
            var subj = JSON.parse(pac).credentialSubject || {};
            if (!(subj.predicateProofs || []).length) { that.toast("PAC built, but no disclosures yet. Run Disclose first."); }
          } catch (e) { /* ignore */ }
        })
        .catch(function (e) { that.error(e); });
    },

    onDownloadAspect: function () { this._download(this._pid() + "-aspect.json", this._cx().getProperty("/aspect")); },
    onDownloadPac: function () { this._download(this._pid() + "-pac.json", this._cx().getProperty("/pac")); },

    _download: function (sName, sText) {
      if (!sText) { return; }
      var a = document.createElement("a");
      a.href = "data:application/json;charset=utf-8," + encodeURIComponent(sText);
      a.download = sName;
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
    },

    // ---- Track A: field disclosure (no tx; value + Merkle inclusion proof) ----

    onDisclose: function () {
      var that = this;
      var sField = this.byId("proofField").getSelectedKey();
      this.callAction("/disclosePassportValue", { passportId: this._pid(), sourceField: sField })
        .then(function (res) {
          that.getView().getModel("disc").setData({
            value: res.value, scaledValue: res.scaledValue, contentRoot: res.contentRoot,
            json: JSON.stringify({
              passportId: res.passportId, sourceField: res.sourceField,
              value: res.value, scaledValue: res.scaledValue, scale: 1000,
              fieldKey: res.fieldKey, contentRoot: res.contentRoot,
              siblings: JSON.parse(res.siblingsJson), dirs: JSON.parse(res.dirsJson),
              contentRootAnchorTx: res.anchorTxHash, unit: res.unit
            }, null, 2)
          });
          that.toast(sField + " disclosed: " + res.value);
          that._refreshAll();
        })
        .catch(function (e) { that.error(e); });
    },

    onDownloadDisclosure: function () {
      var sJson = this.getView().getModel("disc").getProperty("/json");
      this._download(this._pid() + "-disclosure.json", sJson);
    },

    // Per-field predicate presets (human units; the value is scaled x1000 in the
    // service/circuit). Picking a field sets a sensible operator + threshold + unit.
    _FIELD_META: {
      carbonFootprintKgCO2:   { unit: "kg CO₂ / kWh", op: "lessOrEqual",    threshold: 4000 },
      capacityKwh:            { unit: "kWh",           op: "greaterOrEqual", threshold: 60 },
      recycledContentPct:     { unit: "%",             op: "greaterOrEqual", threshold: 16 },
      cycleLife:              { unit: "cycles",        op: "greaterOrEqual", threshold: 3000 },
      roundTripEfficiencyPct: { unit: "%",             op: "greaterOrEqual", threshold: 90 },
      leadContentPpm:         { unit: "ppm",           op: "lessOrEqual",    threshold: 100 },
      recycledCoPct:          { unit: "%",             op: "greaterOrEqual", threshold: 16 },
      recycledLiPct:          { unit: "%",             op: "greaterOrEqual", threshold: 6 },
      recycledNiPct:          { unit: "%",             op: "greaterOrEqual", threshold: 6 }
    },

    onProofFieldChange: function () {
      var m = this._FIELD_META[this.byId("proofField").getSelectedKey()];
      if (!m) { return; }
      this.byId("zkPredicate").setSelectedKey(m.op);
      this.byId("zkThreshold").setValue(String(m.threshold));
      this.byId("zkUnit").setValue(m.unit);
    },

    onProvePredicate: function () {
      var that = this;
      var sOwner = this._session().getProperty("/owner");
      if (!sOwner) { return this.toast("connect your wallet on the list page first"); }
      var sField = this.byId("proofField").getSelectedKey();
      var sPredicate = this.byId("zkPredicate").getSelectedKey();
      var sThreshold = this.byId("zkThreshold").getValue();
      var sUnit = this.byId("zkUnit").getValue() || null;
      if (!sThreshold) { return this.toast("enter a threshold"); }
      this._wallet("Prove predicate with wallet (zk mint)", async function (api, append) {
        append("generating Groth16 proof …");
        var prep = await that.callAction("/prepareWalletPredicate", {
          passportId: that._pid(), sourceField: sField,
          predicate: sPredicate, threshold: sThreshold, unit: sUnit
        });
        if (!prep.isCompliant) {
          append("predicate NOT satisfied — nothing to mint.");
          await that.callAction("/recordWalletPredicate", {
            passportId: that._pid(), sourceField: sField, mode: "zk",
            predicate: sPredicate, threshold: prep.thresholdScaled, unit: sUnit,
            txHash: null, result: false, proofJson: prep.proofJson
          });
          that._refreshAll(); that.toast("predicate not satisfied");
          return;
        }
        append("verifier policy " + prep.policyId);
        append("building zk mint tx, funded by your wallet …");
        var build = await that.httpJson("POST", "/odata/v4/cardano-transaction/BuildMintTransaction", {
          senderAddress: sOwner, recipientAddress: sOwner,
          lovelaceAmount: prep.lovelaceAmount,
          mintActionsJson: prep.mintActionsJson,
          mintingPolicyScript: prep.mintingPolicyScript,
          mintRedeemerJson: prep.mintRedeemerJson,
          inlineDatumJson: prep.inlineDatumJson,
          metadataJson: prep.metadataJson,
          validityStartMs: prep.validityStartMs
        });
        var r = await that._signAndSubmit(api, build, append);
        append("saving in cockpit …");
        await that.callAction("/recordWalletPredicate", {
          passportId: that._pid(), sourceField: sField, mode: "zk",
          predicate: sPredicate, threshold: prep.thresholdScaled, unit: sUnit,
          txHash: r.txHash, result: true, proofJson: prep.proofJson
        });
        that._refreshAll(); append("done. The Groth16 proof was verified on-chain in this tx.");
        that.toast("zk predicate submitted");
      });
    },

    // ---- wallet mode (CIP-30): browser orchestrates the ODATANO HTTP actions ---

    _walletApi: function () { return this.getOwnerComponent()._walletApi || null; },
    _walletName: function () { return this.getOwnerComponent()._walletName || "wallet"; },

    // Open the log dialog and run fnRun(api, append). Shared by attest/grant/revoke.
    _wallet: async function (sTitle, fnRun) {
      var oWallet = new JSONModel({ title: sTitle, log: "", busy: false });
      this.getView().setModel(oWallet, "wallet");
      var append = function (m) { oWallet.setProperty("/log", oWallet.getProperty("/log") + m + "\n"); };
      var that = this;
      if (!this._pWalletLog) {
        this._pWalletLog = Fragment.load({ id: this.getView().getId(), name: "producer.fragment.WalletLogDialog", controller: this })
          .then(function (d) { that.getView().addDependent(d); return d; });
      }
      var oDialog = await this._pWalletLog;
      oDialog.open();
      oWallet.setProperty("/busy", true);
      try {
        var api = this._walletApi();
        if (!api) { append("No wallet connected. Use Connect wallet on the list page first."); return; }
        await fnRun(api, append);
      } catch (e) { append("ERROR: " + ((e && (e.message || e.info)) || JSON.stringify(e))); }
      finally { oWallet.setProperty("/busy", false); }
    },

    /**
     * Shared CIP-30 signing leg, EXACTLY the proven TRACE/FINCA pattern:
     * CreateSigningRequest -> ONE api.signTx(unsignedTxCbor, partial=true) ->
     * pass the wallet's witness set STRAIGHT to SubmitVerifiedTransaction
     * (ODATANO reconstructs the tx server-side and checks the body hash).
     * No browser-side witness merge, no retry popups. Returns { txHash }.
     */
    _signAndSubmit: async function (api, oBuild, append) {
      append("creating signing request for build " + oBuild.id + " …");
      var sig = await this.httpJson("POST", "/odata/v4/cardano-sign/CreateSigningRequest", {
        buildId: oBuild.id, message: "DAYPASS cockpit"
      });
      append("sign in your wallet …");
      var sSignedCbor = await api.signTx(sig.unsignedTxCbor, true);
      append("signature received, verifying and submitting …");
      var sub = await this.httpJson("POST", "/odata/v4/cardano-sign/SubmitVerifiedTransaction", {
        signingRequestId: sig.id || sig.ID,
        signedTxCbor: sSignedCbor,
        signerType: "browser-wallet",
        signerInfo: this._walletName()
      });
      append("submitted: " + sub.txHash);
      append("explorer: https://preview.cardanoscan.io/transaction/" + sub.txHash);
      return { txHash: sub.txHash };
    },

    onAttestWithWallet: function () {
      var that = this;
      var sOwner = this._session().getProperty("/owner");
      if (!sOwner) { return this.toast("connect your wallet on the list page first"); }
      this._wallet("Attest with wallet (mint passport NFT)", async function (api, append) {
        append("preparing mint data, policy bound to your wallet key …");
        var prep = await that.callAction("/prepareWalletMint", { passportId: that._pid(), walletAddress: sOwner });
        append("policy " + prep.policyId);
        append("building mint tx, funded by your wallet …");
        var build = await that.httpJson("POST", "/odata/v4/cardano-transaction/BuildMintTransaction", {
          senderAddress: sOwner, recipientAddress: sOwner,
          lovelaceAmount: prep.lovelaceAmount,
          mintActionsJson: prep.mintActionsJson,
          mintingPolicyScript: prep.mintingPolicyScript,
          scriptParamsJson: prep.scriptParamsJson,
          requiredSignersJson: prep.requiredSignersJson,
          metadataJson: prep.metadataJson,
          validityStartMs: prep.validityStartMs
        });
        var r = await that._signAndSubmit(api, build, append);
        append("saving in cockpit …");
        await that.callAction("/recordWalletMint", {
          passportId: that._pid(), txHash: r.txHash, unit: prep.unit, policyId: prep.policyId
        });
        that._refreshAll(); append("done. Confirmation is tracked in the Transactions tab.");
        that.toast("wallet mint submitted");
      });
    },

    onReattestWithWallet: function () {
      var that = this;
      var sOwner = this._session().getProperty("/owner");
      if (!sOwner) { return this.toast("connect your wallet on the list page first"); }
      this._wallet("Re-attest with wallet (anchor new version)", async function (api, append) {
        append("recomputing payload from current data …");
        var prep = await that.callAction("/prepareWalletReattest", { passportId: that._pid() });
        if (prep.mode === "unchanged") {
          append("payload unchanged — nothing to anchor.");
          that.toast("no changes to anchor");
          return;
        }
        append("anchor v" + prep.version + ", building metadata tx …");
        var build = await that.httpJson("POST", "/odata/v4/cardano-transaction/BuildTransactionWithMetadata", {
          senderAddress: sOwner, recipientAddress: sOwner,
          lovelaceAmount: prep.lovelaceAmount,
          metadataJson: prep.metadataJson
        });
        var r = await that._signAndSubmit(api, build, append);
        append("saving in cockpit …");
        await that.callAction("/recordWalletReattest", {
          passportId: that._pid(), txHash: r.txHash,
          payloadHash: prep.payloadHash, version: prep.version
        });
        that._refreshAll(); append("done. Confirmation is tracked in the Transactions tab.");
        that.toast("wallet reattest submitted");
      });
    },

    onGrantWithWallet: function (sOp) {
      var that = this;
      var sOwner = this._session().getProperty("/owner");
      if (!sOwner) { return this.toast("connect your wallet on the list page first"); }
      var sGrantee = this.byId("granteePartner").getSelectedKey();
      if (!sGrantee) { return this.toast("select a partner"); }
      var iLevel = parseInt(this.byId("grantLevel").getSelectedKey(), 10);
      this._wallet((sOp === "grant" ? "Grant" : "Revoke") + " with wallet (audit anchor)", async function (api, append) {
        append("preparing " + sOp + " anchor metadata …");
        var prep = await that.callAction("/prepareWalletAnchor", {
          passportId: that._pid(), op: sOp, grantee: sGrantee, level: iLevel
        });
        append("building metadata tx …");
        var build = await that.httpJson("POST", "/odata/v4/cardano-transaction/BuildTransactionWithMetadata", {
          senderAddress: sOwner, recipientAddress: sOwner,
          lovelaceAmount: prep.lovelaceAmount,
          metadataJson: prep.metadataJson
        });
        var r = await that._signAndSubmit(api, build, append);
        append("saving in cockpit …");
        await that.callAction("/recordWalletDisclosure", {
          passportId: that._pid(), grantee: prep.grantee, level: iLevel, op: sOp, txHash: r.txHash
        });
        that._refreshAll(); append("done."); that.toast("wallet " + sOp + " submitted");
      });
    },

    onRevokePassport: function () {
      var that = this;
      var sOwner = this._session().getProperty("/owner");
      if (!sOwner) { return this.toast("connect your wallet on the list page first"); }
      MessageBox.confirm("Burn the passport NFT? The passport becomes revoked; the anchor history stays on-chain.", {
        title: "Revoke passport",
        onClose: function (sAction) {
          if (sAction !== MessageBox.Action.OK) { return; }
          that._wallet("Revoke passport (burn NFT)", async function (api, append) {
            append("locating the passport NFT in your wallet …");
            var prep = await that.callAction("/prepareWalletBurn", { passportId: that._pid(), walletAddress: sOwner });
            append("building burn tx …");
            var build = await that.httpJson("POST", "/odata/v4/cardano-transaction/BuildMintTransaction", {
              senderAddress: sOwner, recipientAddress: sOwner,
              lovelaceAmount: prep.lovelaceAmount,
              mintActionsJson: prep.mintActionsJson,
              mintingPolicyScript: prep.mintingPolicyScript,
              scriptParamsJson: prep.scriptParamsJson,
              requiredSignersJson: prep.requiredSignersJson,
              forceInputsJson: prep.forceInputsJson,
              metadataJson: prep.metadataJson,
              validityStartMs: prep.validityStartMs
            });
            var r = await that._signAndSubmit(api, build, append);
            append("saving in cockpit …");
            await that.callAction("/recordWalletBurn", { passportId: that._pid(), txHash: r.txHash });
            that._refreshAll(); append("done. Confirmation is tracked in the Transactions tab.");
            that.toast("wallet burn submitted");
          });
        }
      });
    },

    onWalletLogClose: function () {
      this.byId("walletLogDialog").close();
    },

    // ---- share with supplier (resolve link + QR + auto-grant + credential) ----

    onShare: function () {
      var oCtx = this.getView().getBindingContext();
      if (!oCtx) { return; }
      var sHash = oCtx.getProperty("payloadHash") || "";
      var sPid = oCtx.getProperty("passportId") || "";
      this.getView().setModel(new JSONModel({
        passportId: sPid,
        payloadHash: sHash,
        resolveUrl: window.location.origin + "/resolve/" + sHash,
        qrUrl: "/qr/" + encodeURIComponent(sPid) + ".png",
        grantee: "",
        level: "2"
      }), "share");
      var that = this;
      if (!this._pShare) {
        this._pShare = Fragment.load({
          id: this.getView().getId(),
          name: "producer.fragment.ShareDialog",
          controller: this
        }).then(function (oDialog) { that.getView().addDependent(oDialog); return oDialog; });
      }
      this._pShare.then(function (oDialog) { oDialog.open(); });
    },

    onShareGrant: function () {
      var oShare = this.getView().getModel("share");
      var sGrantee = (oShare.getProperty("/grantee") || "").trim();
      if (!sGrantee) { return this.toast("enter the supplier's grantee id or DID/BPN"); }
      var that = this;
      // ACL-only grant (no anchor tx); use the Grant button for a wallet-signed audit anchor.
      this.callAction("/grantPassportDisclosure", {
        passportId: this._pid(), grantee: sGrantee, level: parseInt(oShare.getProperty("/level"), 10), anchor: false
      }).then(function (res) { that.toast("supplier granted: " + res.mode); that._refreshAll(); })
        .catch(function (e) { that.error(e); });
    },

    onCopyLink: function () {
      var sUrl = this.getView().getModel("share").getProperty("/resolveUrl");
      var that = this;
      if (navigator.clipboard) {
        navigator.clipboard.writeText(sUrl).then(function () { that.toast("resolve link copied"); });
      } else { this.toast(sUrl); }
    },

    onDownloadCredential: function () {
      var that = this;
      var oOp = this._model().bindContext("/passportCredential(...)");
      oOp.setParameter("passportId", this._pid());
      this.setBusy(true);
      oOp.invoke().then(function () {
        var oRes = oOp.getBoundContext().getObject();
        var sJson = (oRes && oRes.value) || oRes;
        var oBlob = new Blob([sJson], { type: "application/json" });
        var oUrl = window.URL.createObjectURL(oBlob);
        var oA = document.createElement("a");
        oA.href = oUrl; oA.download = "battery-passport-credential.json";
        document.body.appendChild(oA); oA.click(); oA.remove();
        window.URL.revokeObjectURL(oUrl);
        that.toast("credential downloaded");
      }).catch(function (e) { that.error(e); }).finally(function () { that.setBusy(false); });
    },

    onShareClose: function () {
      this.byId("shareDialog").close();
    }
  });
});


