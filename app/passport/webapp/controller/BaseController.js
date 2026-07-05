sap.ui.define([
  "sap/ui/core/mvc/Controller",
  "sap/ui/model/json/JSONModel"
], function (Controller, JSONModel) {
  "use strict";

  /**
   * Shared behaviour for the three tier views. Each view has a master List of
   * passports (id "passportList") and a detail container (id "detail"); selecting
   * a passport element-binds the detail to that row. The fields each view renders
   * differ per tier; the data they receive is already redacted server-side.
   */
  return Controller.extend("passport.controller.BaseController", {

    onInit: function () {
      // Per-view state of the on-chain verification panel.
      this.getView().setModel(new JSONModel({ state: "", busy: false, checks: [] }), "verify");
    },

    onPassportSelect: function (oEvent) {
      var oItem = oEvent.getParameter("listItem") || oEvent.getSource();
      var oCtx = oItem.getBindingContext();
      if (oCtx) { this._bindDetail(oCtx); }
    },

    _bindDetail: function (oCtx) {
      var oDetail = this.byId("detail");
      oDetail.bindElement({ path: oCtx.getPath() });
      oDetail.setVisible(true);
      var oEmpty = this.byId("emptyDetail");
      if (oEmpty) { oEmpty.setVisible(false); }
      var oVerify = this.getView().getModel("verify");
      if (oVerify) { oVerify.setData({ state: "", busy: false, checks: [] }); }
    },

    // On-chain verification: public evidence endpoint, no auth required.
    onVerifyOnChain: function () {
      var oDetail = this.byId("detail");
      var oCtx = oDetail && oDetail.getBindingContext();
      var sPid = oCtx && oCtx.getProperty("passportId");
      var oVerify = this.getView().getModel("verify");
      if (!sPid || !oVerify) { return; }
      oVerify.setProperty("/busy", true);
      fetch("/verify/" + encodeURIComponent(sPid))
        .then(function (res) { return res.json(); })
        .then(function (data) {
          oVerify.setData({
            state: data.verified === true ? "ok" : "bad",
            busy: false,
            checks: data.checks || (data.error ? [{ check: data.error, pass: false }] : [])
          });
        })
        .catch(function (err) {
          oVerify.setData({ state: "bad", busy: false, checks: [{ check: String(err), pass: false }] });
        });
    },

    // T23: when arriving via the QR resolver (?p=<passportId>), preselect that
    // battery as soon as the list has rendered. Consumed once.
    onListUpdateFinished: function () {
      var oSession = this.getOwnerComponent().getModel("session");
      var sPid = oSession.getProperty("/pendingPassport");
      if (!sPid) { return; }
      var oList = this.byId("passportList");
      var aItems = oList.getItems();
      for (var i = 0; i < aItems.length; i++) {
        var oCtx = aItems[i].getBindingContext();
        if (oCtx && oCtx.getProperty("passportId") === sPid) {
          oList.setSelectedItem(aItems[i]);
          this._bindDetail(oCtx);
          oSession.setProperty("/pendingPassport", "");
          break;
        }
      }
    },

    formatQrSrc: function (sPassportId) {
      return sPassportId ? "/qr/" + encodeURIComponent(sPassportId) + ".png" : "";
    },

    // ---- Formatters ----

    formatCategory: function (s) {
      switch (s) {
        case "EV":         return "Electric Vehicle";
        case "INDUSTRIAL": return "Industrial";
        case "LMT":        return "Light Means of Transport";
        default:           return s || "";
      }
    },

    formatPerfState: function (s) {
      if (!s) { return "None"; }
      return (s === "A" || s === "B") ? "Success" : (s === "C" || s === "D") ? "Warning" : "Error";
    },

    formatTxLink: function (sHash) {
      return sHash ? sHash : "not anchored";
    },

    formatExplorerHref: function (sHash) {
      return sHash ? "https://preview.cardanoscan.io/transaction/" + String(sHash).replace(/^0x/, "") : "";
    },

    formatAssetHref: function (sFingerprint) {
      return sFingerprint ? "https://preview.cardanoscan.io/token/" + sFingerprint : "";
    }
  });
});
