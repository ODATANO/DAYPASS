sap.ui.define([
  "sap/ui/core/mvc/Controller",
  "sap/m/MessageToast",
  "sap/m/MessageBox"
], function (Controller, MessageToast, MessageBox) {
  "use strict";

  // Demo credentials of the mocked producer user (srv/auth.js). The cockpit is
  // a producer tool; a production deployment replaces this with real auth.
  var AUTH = "Basic " + window.btoa("producer:producer");

  return Controller.extend("producer.controller.BaseController", {

    _model: function () { return this.getOwnerComponent().getModel(); },
    _session: function () { return this.getOwnerComponent().getModel("session"); },
    _router: function () { return this.getOwnerComponent().getRouter(); },

    setBusy: function (b) { this._session().setProperty("/busy", !!b); },

    toast: function (s) { MessageToast.show(s); },
    error: function (e) { MessageBox.error(String((e && (e.message || e.error && e.error.message)) || e)); },

    /**
     * Invoke an unbound OData v4 action (e.g. "/createPassport") with parameters,
     * returning the action result object. Shows a global busy state while running.
     */
    callAction: function (sPath, oParams) {
      var oModel = this._model();
      var oOp = oModel.bindContext(sPath + "(...)");
      Object.keys(oParams || {}).forEach(function (k) { oOp.setParameter(k, oParams[k]); });
      this.setBusy(true);
      var that = this;
      return oOp.invoke()
        .then(function () { return oOp.getBoundContext().getObject(); })
        .finally(function () { that.setBusy(false); });
    },

    /**
     * Direct JSON call to any service on this host (wallet mode drives the
     * ODATANO plugin actions over HTTP — the proven request isolation).
     */
    httpJson: async function (sMethod, sPath, oBody) {
      var res = await fetch(sPath, {
        method: sMethod,
        headers: { "Content-Type": "application/json", "Authorization": AUTH },
        body: oBody !== undefined ? JSON.stringify(oBody) : undefined
      });
      var text = await res.text();
      var json;
      try { json = JSON.parse(text); } catch (e) { json = { raw: text }; }
      if (!res.ok) {
        throw new Error((json && json.error && json.error.message) || (sMethod + " " + sPath + " -> HTTP " + res.status));
      }
      return json;
    },

    authHeader: function () { return AUTH; },

    explorerTx: function (sHash) {
      return sHash ? "https://preview.cardanoscan.io/transaction/" + String(sHash).replace(/^0x/, "") : "";
    },

    // Formatter: submit is enabled until the passport is anchored.
    notAnchored: function (sStatus) { return sStatus !== "anchored"; }
  });
});
