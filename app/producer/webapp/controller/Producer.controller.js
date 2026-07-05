sap.ui.define([
  "producer/controller/BaseController",
  "sap/ui/core/Fragment",
  "sap/ui/model/json/JSONModel",
  "sap/ui/model/Filter",
  "sap/ui/model/FilterOperator",
  "producer/lib/cardano-wallet"
], function (BaseController, Fragment, JSONModel, Filter, FilterOperator, wallet) {
  "use strict";

  // Prefilled battery-passport example (EU 2023/1542 Annex XIII), editable in the
  // create dialog. Public Point-1 fields + the private (restricted) content.
  function defaultDraft() {
    return {
      passportId: "BAT-PROD-0001",
      manufacturerId: "DE-CELLCO-001",
      batteryCategory: "EV",
      model: "PowerCell EV-75",
      manufactureDate: "2026-03-15",
      weightKg: 432.5,
      performanceClass: "B",
      battery: {
        serialNumber: "SN-AX-0001",
        cellChemistry: "NMC-811",
        capacityKwh: 75.0,
        carbonFootprintKgCO2: 3412.75,
        supplierName: "CathodeWorks GmbH",
        recycledContentPct: 16.5,
        cycleLife: 4200,
        roundTripEfficiencyPct: 92.5,
        leadContentPpm: 45.0
      },
      recycled: [
        { material: "Co", recycledPercentage: 16.5, sourceSupplierName: "ReCobalt Recyclers SA" },
        { material: "Li", recycledPercentage: 8.25, sourceSupplierName: "LiLoop Recycling BV" },
        { material: "Ni", recycledPercentage: 12.0, sourceSupplierName: "NickelBack Materials Oy" }
      ],
      diligenceDocType: "supply-chain-due-diligence-report",
      submit: false
    };
  }

  return BaseController.extend("producer.controller.Producer", {

    onInit: function () {
      // The passport list is owner-gated: it appears after a CIP-30 wallet is
      // connected and shows ONLY the passports owned by that wallet address.
      // Every chain action (attest, grant, revoke, burn, zk) signs in the wallet.
      this._hookCount();
    },

    /** Scope the list to the connected wallet; nothing matches while disconnected. */
    _applyOwnerFilter: function () {
      var oBinding = this.byId("passportTable").getBinding("items");
      if (!oBinding) { return; }
      var sOwner = this._session().getProperty("/owner");
      oBinding.filter(new Filter("owner", FilterOperator.EQ, sOwner || "__not_connected__"));
    },

    _hookCount: function () {
      var oBinding = this.byId("passportTable").getBinding("items");
      if (!oBinding || this._countHooked) { return; }
      this._countHooked = true;
      var that = this;
      oBinding.attachChange(function () {
        var n = 0;
        try {
          var oHeader = oBinding.getHeaderContext && oBinding.getHeaderContext();
          var v = oHeader && oHeader.getProperty("$count");
          n = (v == null) ? 0 : v;
        } catch (e) { n = 0; }
        that._session().setProperty("/passportCount", n);
      });
    },

    // ---- CIP-30 wallet SIGN-IN (proof of key control, not just enable()) ----
    // Pattern from TRACE: enable -> address (CBOR-wrapper-stripped) -> the user
    // SIGNS a human-readable message (signData / COSE_Sign1) -> the backend
    // verifies it statelessly (VerifyDataSignature) and confirms the signer key
    // matches the address. Only then is the wallet considered connected.

    onConnectWallet: async function () {
      var aWallets = wallet.listWallets();
      if (!aWallets.length) {
        return this.error("No CIP-30 Cardano wallet found. Install and unlock Lace or Eternl on the Preview network.");
      }
      if (aWallets.length === 1) {
        return this._signInWith(aWallets[0]);
      }
      // Several extensions detected (e.g. a Midnight-only Lace next to Eternl):
      // let the user pick instead of failing on the wrong one.
      var that = this;
      var oSheet = new sap.m.ActionSheet({
        title: "Choose a Cardano wallet",
        buttons: aWallets.map(function (w) {
          return new sap.m.Button({
            text: w.name,
            icon: "sap-icon://wallet",
            press: function () { that._signInWith(w); }
          });
        })
      });
      this.getView().addDependent(oSheet);
      oSheet.openBy(this.byId("connectWalletBtn") || this.getView());
    },

    /** Reject after `ms` so a hanging wallet popup cannot block the UI forever
     * (the popup itself may stay open; the session simply is not established). */
    _withTimeout: function (oPromise, iMs, sMsg) {
      return Promise.race([oPromise, new Promise(function (resolve, reject) {
        setTimeout(function () { reject(new Error(sMsg)); }, iMs);
      })]);
    },

    // CIP-30 connect + sign-in: enable -> collect the wallet's addresses ->
    // pick the FUNDED one (Eternl multi-address wallets use a different payment
    // key per address, so index 0 is often empty) -> the wallet SIGNS a server
    // challenge (signData, COSE_Sign1) -> walletLogin verifies it and returns
    // the session token that scopes the whole producer API to this wallet.
    _signInWith: async function (oPick) {
      var oSession = this._session();
      try {
        this.setBusy(true);
        var api;
        try {
          api = await wallet.connect(oPick.key);
        } catch (eEnable) {
          var sMsg = String((eEnable && (eEnable.message || eEnable.info)) || eEnable);
          return this.error(oPick.name + ": " + sMsg +
            "\n\nThis extension has no usable CARDANO account for example a Midnight-only Lace. " +
            "Create/restore a Cardano wallet on the Preview network in that extension, or pick a different wallet.");
        }

        var aCands = await wallet.candidateAddresses(api);
        if (!aCands.length) { return this.error(oPick.name + " returned no addresses"); }

        // Pick the first candidate holding funds (server-side balance lookup).
        var oAddr = null;
        for (var i = 0; i < aCands.length; i++) {
          try {
            var oInfo = await this.httpJson("POST", "/odata/v4/cardano-odata/GetAddressByBech32", {
              address: aCands[i].bech32
            });
            if (Number(oInfo.totalLovelace || 0) > 0) { oAddr = aCands[i]; break; }
          } catch (e) { /* address unknown to the chain yet — keep scanning */ }
        }
        if (!oAddr) {
          oAddr = aCands[0];
          this.toast("note: none of the wallet addresses holds tADA yet. Fund " + oAddr.bech32.slice(0, 20) + "… first");
        }

        // Proof of key control: sign the server challenge in the wallet.
        var oChallenge = await this.callAction("/walletLoginChallenge", { address: oAddr.bech32 });
        this.toast("confirm the sign-in message in " + oPick.name);
        var oSigned = await this._withTimeout(
          wallet.signIn(api, oAddr.hex, oChallenge.message),
          120000,
          oPick.name + " did not answer the sign-in request. Close its popup and try again."
        );
        var oLogin = await this.callAction("/walletLogin", {
          nonce: oChallenge.nonce,
          coseSignature: oSigned.coseSignature,
          coseKey: oSigned.coseKey
        });
        this._model().changeHttpHeaders({ "x-wallet-session": oLogin.token });

        this.getOwnerComponent()._walletApi = api;
        this.getOwnerComponent()._walletName = oPick.name;
        oSession.setProperty("/walletToken", oLogin.token);
        oSession.setProperty("/owner", oAddr.bech32);
        oSession.setProperty("/ownerVkh", oAddr.vkh);
        oSession.setProperty("/ownerShort", oAddr.bech32.slice(0, 16) + "…" + oAddr.bech32.slice(-6));
        oSession.setProperty("/walletConnected", true);
        this._applyOwnerFilter();
        this.toast(oPick.name + " signed in: " + oSession.getProperty("/ownerShort"));
      } catch (e) {
        this.error(e);
      } finally {
        this.setBusy(false);
      }
    },

    onDisconnectWallet: function () {
      var that = this;
      var oModel = this._model();
      var pLogout = this._session().getProperty("/walletToken")
        ? this.callAction("/walletLogout", {}).catch(function () { /* session expiry handles it */ })
        : Promise.resolve();
      this.getOwnerComponent()._walletApi = null;
      this.getOwnerComponent()._walletName = "";
      var oSession = this._session();
      oSession.setProperty("/walletToken", "");
      oSession.setProperty("/owner", "");
      oSession.setProperty("/ownerVkh", "");
      oSession.setProperty("/ownerShort", "");
      oSession.setProperty("/walletConnected", false);
      pLogout.then(function () {
        // Not while requests are in flight — UI5 rejects that.
        oModel.changeHttpHeaders({ "x-wallet-session": null });
        that._applyOwnerFilter();
      });
      this.toast("wallet disconnected");
    },

    onOpen: function (oEvent) {
      // Key from the binding PATH (always present), not getProperty("ID") which
      // can be undefined under autoExpandSelect. Path is "/Passports(<key>)".
      var oCtx = oEvent.getParameter("listItem").getBindingContext();
      var aMatch = oCtx && oCtx.getPath().match(/\(([^)]+)\)/);
      if (!aMatch) { return; }
      this._router().navTo("detail", { key: encodeURIComponent(aMatch[1]) });
    },

    onRefresh: function () {
      var oTable = this.byId("passportTable");
      if (oTable && oTable.getBinding("items")) { oTable.getBinding("items").refresh(); }
    },

    // ---- create ----

    onCreate: function () {
      if (!this._session().getProperty("/walletConnected")) {
        return this.toast("connect your wallet first — new passports belong to the connected wallet");
      }
      var that = this;
      this.getView().setModel(new JSONModel(defaultDraft()), "create");
      if (!this._pCreate) {
        this._pCreate = Fragment.load({
          id: this.getView().getId(),
          name: "producer.fragment.CreatePassportDialog",
          controller: this
        }).then(function (oDialog) { that.getView().addDependent(oDialog); return oDialog; });
      }
      this._pCreate.then(function (oDialog) { oDialog.open(); });
    },

    onCreateCancel: function () {
      this.byId("createDialog").close();
    },

    // ---- register partner (self-service registry) ----

    onRegisterPartner: function () {
      var that = this;
      this.getView().setModel(new JSONModel({
        did: "BPNL000000000XYZ", name: "New Partner Co", role: "recycler", secret: "secret"
      }), "register");
      if (!this._pRegister) {
        this._pRegister = Fragment.load({
          id: this.getView().getId(),
          name: "producer.fragment.RegisterPartnerDialog",
          controller: this
        }).then(function (oDialog) { that.getView().addDependent(oDialog); return oDialog; });
      }
      this._pRegister.then(function (oDialog) { oDialog.open(); });
    },

    onRegisterCancel: function () {
      this.byId("registerDialog").close();
    },

    onRegisterSave: function () {
      var d = this.getView().getModel("register").getData();
      if (!d.did || !d.secret) { return this.toast("DID/BPN and secret are required"); }
      var that = this;
      this.setBusy(true);
      // registerPartner lives on PassportService (public self-service); call it
      // directly (the producer app is authenticated as the mocked producer).
      fetch("/api/v1/passport/registerPartner", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": "Basic " + window.btoa("producer:producer") },
        body: JSON.stringify({ did: d.did, name: d.name, role: d.role, secret: d.secret })
      }).then(function (r) {
        if (!r.ok) { return r.text().then(function (t) { throw new Error(t || ("HTTP " + r.status)); }); }
        return r.json();
      }).then(function (res) {
        that.byId("registerDialog").close();
        var oP = that.byId("partnersTable");
        if (oP && oP.getBinding("items")) { oP.getBinding("items").refresh(); }
        that.toast("partner registered: " + (res.name || res.did) + " · granteeId " + String(res.granteeId).slice(0, 10) + "…");
      }).catch(function (e) { that.error(e); })
        .finally(function () { that.setBusy(false); });
    },

    onCreateSave: function () {
      var d = this.getView().getModel("create").getData();
      var passportJson = JSON.stringify({
        passportId: d.passportId,
        manufacturerId: d.manufacturerId,
        batteryCategory: d.batteryCategory,
        model: d.model,
        manufactureDate: d.manufactureDate,
        weightKg: Number(d.weightKg),
        performanceClass: d.performanceClass,
        batteries: [{
          serialNumber: d.battery.serialNumber,
          cellChemistry: d.battery.cellChemistry,
          capacityKwh: Number(d.battery.capacityKwh),
          carbonFootprintKgCO2: Number(d.battery.carbonFootprintKgCO2),
          supplierName: d.battery.supplierName,
          recycledContentPct: Number(d.battery.recycledContentPct),
          cycleLife: Number(d.battery.cycleLife),
          roundTripEfficiencyPct: Number(d.battery.roundTripEfficiencyPct),
          leadContentPpm: Number(d.battery.leadContentPpm)
        }],
        recycledMaterials: (d.recycled || []).map(function (r) {
          return { material: r.material, recycledPercentage: Number(r.recycledPercentage), sourceSupplierName: r.sourceSupplierName };
        }),
        diligenceDocs: d.diligenceDocType ? [{ docType: d.diligenceDocType }] : []
      });

      var that = this;
      this.callAction("/createPassport", {
        passportJson: passportJson,
        submit: false,
        owner: this._session().getProperty("/owner")
      }).then(function (res) {
        that.byId("createDialog").close();
        that.onRefresh();
        that.toast("Passport " + res.passportId + " created. Anchor it via Attest");
      }).catch(function (e) { that.error(e); });
    }
  });
});

