<script>
import { parse } from "cidr-tools";
import "@/utilities/wireguard.js";
import { WireguardConfigurationsStore } from "@/stores/WireguardConfigurationsStore.js";
import { fetchPost } from "@/utilities/fetch.js";
import LocaleText from "@/components/text/localeText.vue";

export default {
  name: "newConfiguration",
  components: { LocaleText },
  setup() {
    const store = WireguardConfigurationsStore();
    return { store };
  },
  data() {
    return {
      newConfiguration: {
        ConfigurationName: "",
        Address: "",
        ListenPort: "",
        PrivateKey: "",
        PublicKey: "",
        PresharedKey: "",
        PreUp: "",
        PreDown: "",
        PostUp: "",
        PostDown: "",
        Jc: "",
        Jmin: "",
        Jmax: "",
        S1: "",
        S2: "",
        H1: "",
        H2: "",
        H3: "",
        H4: "",
		Protocol: "wg"
      },
      descriptions: {
      Jc: "Defines the number of junk packets to send before the handshake (1-128). Recommended range: 3-10.",
      Jmin: "Specifies the minimum size of the junk packet payload in bytes (0-1280).",
      Jmax: "Specifies the maximum size of the junk packet payload in bytes (0-1280). Jmin must be less than Jmax.",
      S1: "Defines how many bytes of junk data are placed before the actual WireGuard data in the handshake initiation (15-150).",
      S2: "Defines how many bytes of junk data are placed before the actual WireGuard data in the handshake response (15-150). S1 + 56 must not equal S2.",
      H1: "Custom type for Handshake Initiation. Must be unique and between 5 and 2147483647.",
      H2: "Custom type for Handshake Response. Must be unique and between 5 and 2147483647.",
      H3: "Custom type for another WireGuard message. Must be unique and between 5 and 2147483647.",
      H4: "Custom type for yet another WireGuard message. Must be unique and between 5 and 2147483647."
    },
      numberOfAvailableIPs: "0",
      error: false,
      errorMessage: "",
      success: false,
      loading: false,
    };
  },
  created() {
    this.wireguardGenerateKeypair();
    this.generateRandomValues();
  },
  methods: {
    wireguardGenerateKeypair() {
      const wg = window.wireguard.generateKeypair();
      this.newConfiguration.PrivateKey = wg.privateKey;
      this.newConfiguration.PublicKey = wg.publicKey;
      this.newConfiguration.PresharedKey = wg.presharedKey;
    },
    generateRandomValues() {
      this.newConfiguration.Jc = Math.floor(Math.random() * 8) + 3;
      this.newConfiguration.Jmin = Math.floor(Math.random() * 50);
      this.newConfiguration.Jmax = Math.floor(Math.random() * (1280 - this.newConfiguration.Jmin)) + this.newConfiguration.Jmin + 1;
      do {
        this.newConfiguration.S1 = Math.floor(Math.random() * 136) + 15;
      } while (this.newConfiguration.S1 + 56 === this.newConfiguration.S2);
      do {
        this.newConfiguration.S2 = Math.floor(Math.random() * 136) + 15;
      } while (this.newConfiguration.S1 + 56 === this.newConfiguration.S2);
      let hValues = new Set();
      while (hValues.size < 4) {
        hValues.add(Math.floor(Math.random() * (2147483647 - 5 + 1)) + 5);
      }
      [this.newConfiguration.H1, this.newConfiguration.H2, this.newConfiguration.H3, this.newConfiguration.H4] = [...hValues];
    },
    validateHValues() {
    let hValues = [
      this.newConfiguration.H1,
      this.newConfiguration.H2,
      this.newConfiguration.H3,
      this.newConfiguration.H4
    ];
    let uniqueHValues = new Set(hValues.filter((v) => v >= 5 && v <= 2147483647));
    let isValid = hValues.length === uniqueHValues.size;

    hValues.forEach((value, index) => {
      let ele = document.querySelector(`#H${index + 1}`);
      ele.classList.remove("is-invalid", "is-valid");
      if (!isValid || value < 5 || value > 2147483647) {
        ele.classList.add("is-invalid");
      } else {
        ele.classList.add("is-valid");
      }
    });
  },
  async saveNewConfiguration() {
    if (this.validateParameters() && this.goodToSubmit) {
      this.loading = true;
      const apiData = this.prepareApiData();
      await fetchPost("/api/addWireguardConfiguration", apiData, async (res) => {
        if (res.status) {
          this.success = true;
          await this.store.getConfigurations();
          this.$router.push(`/configuration/${this.newConfiguration.ConfigurationName}/peers`);
        } else {
          this.error = true;
          this.errorMessage = res.message;
          document.querySelector(`#${res.data}`).classList.remove("is-valid");
          document.querySelector(`#${res.data}`).classList.add("is-invalid");
          this.loading = false;
        }
      });
    }
  },
    prepareApiData() {
      const {
        ConfigurationName,
        Address,
        ListenPort,
        PrivateKey,
        PublicKey,
        PresharedKey,
        PreUp,
        PreDown,
        PostUp,
        PostDown,
        Jc,
        Jmin,
        Jmax,
        S1,
        S2,
        H1,
        H2,
        H3,
        H4,
		Protocol
      } = this.newConfiguration;

      const apiData = {
        ConfigurationName,
        Address,
        ListenPort,
        PrivateKey,
        PublicKey,
        PresharedKey,
        PreUp,
        PreDown,
        PostUp,
        PostDown,
		Protocol,
      };

      if (this.newConfiguration.Protocol === 'awg') {
        Object.assign(apiData, {
          Jc,
          Jmin,
          Jmax,
          S1,
          S2,
          H1,
          H2,
          H3,
          H4,
        });
      }

      return apiData;
    },
    async saveNewConfiguration() {
      if (this.goodToSubmit) {
        this.loading = true;
        const apiData = this.prepareApiData(); // Use the prepared API data
        await fetchPost("/api/addWireguardConfiguration", apiData, async (res) => {
          if (res.status) {
            this.success = true;
            await this.store.getConfigurations();
            this.$router.push(`/configuration/${this.newConfiguration.ConfigurationName}/peers`);
          } else {
            this.error = true;
            this.errorMessage = res.message;
            document.querySelector(`#${res.data}`).classList.remove("is-valid");
            document.querySelector(`#${res.data}`).classList.add("is-invalid");
            this.loading = false;
          }
        });
      }
    },
  },
  computed: {
    goodToSubmit() {
      let requirements = ["ConfigurationName", "Address", "ListenPort", "PrivateKey"];
      let elements = [...document.querySelectorAll("input[required]")];
      return (
        requirements.find((x) => {
          return this.newConfiguration[x].length === 0;
        }) === undefined &&
        elements.find((x) => {
          return x.classList.contains("is-invalid");
        }) === undefined
      );
    },
  },
  watch: {
    "newConfiguration.Address"(newVal) {
      let ele = document.querySelector("#Address");
      ele.classList.remove("is-invalid", "is-valid");
      try {
        if (newVal.trim().split("/").filter((x) => x.length > 0).length !== 2) {
          throw Error();
        }
        let p = parse(newVal);
        let i = p.end - p.start;
        this.numberOfAvailableIPs = i.toLocaleString();
        ele.classList.add("is-valid");
      } catch (e) {
        this.numberOfAvailableIPs = "0";
        ele.classList.add("is-invalid");
      }
    },
    "newConfiguration.ListenPort"(newVal) {
      let ele = document.querySelector("#ListenPort");
      ele.classList.remove("is-invalid", "is-valid");

      if (newVal < 0 || newVal > 65353 || !Number.isInteger(newVal)) {
        ele.classList.add("is-invalid");
      } else {
        ele.classList.add("is-valid");
      }
    },
    "newConfiguration.ConfigurationName"(newVal) {
      let ele = document.querySelector("#ConfigurationName");
      ele.classList.remove("is-invalid", "is-valid");
      if (
        !/^[a-zA-Z0-9_=+.-]{1,15}$/.test(newVal) ||
        newVal.length === 0 ||
        this.store.Configurations.find((x) => x.Name === newVal)
      ) {
        ele.classList.add("is-invalid");
      } else {
        ele.classList.add("is-valid");
      }
    },
    "newConfiguration.PrivateKey"(newVal) {
      let ele = document.querySelector("#PrivateKey");
      ele.classList.remove("is-invalid", "is-valid");

      try {
        wireguard.generatePublicKey(newVal);
        ele.classList.add("is-valid");
      } catch (e) {
        ele.classList.add("is-invalid");
      }
    },
    "newConfiguration.Jc"(newVal) {
    let ele = document.querySelector("#Jc");
    ele.classList.remove("is-invalid", "is-valid");
    if (newVal < 1 || newVal > 128 || !Number.isInteger(+newVal)) {
      ele.classList.add("is-invalid");
    } else {
      ele.classList.add("is-valid");
    }
  },
  "newConfiguration.Jmin"(newVal) {
    let ele = document.querySelector("#Jmin");
    ele.classList.remove("is-invalid", "is-valid");
    const Jmax = this.newConfiguration.Jmax;
    if (
      newVal < 0 || 
      newVal > 1280 || 
      (Jmax !== "" && +newVal >= +Jmax)
    ) {
      ele.classList.add("is-invalid");
    } else {
      ele.classList.add("is-valid");
    }
  },
  "newConfiguration.Jmax"(newVal) {
    let ele = document.querySelector("#Jmax");
    ele.classList.remove("is-invalid", "is-valid");
    const Jmin = this.newConfiguration.Jmin;
    if (
      newVal <= 0 || 
      newVal > 1280 || 
      (Jmin !== "" && +newVal <= +Jmin)
    ) {
      ele.classList.add("is-invalid");
    } else {
      ele.classList.add("is-valid");
    }
  },
  "newConfiguration.S1"(newVal) {
    let ele = document.querySelector("#S1");
    ele.classList.remove("is-invalid", "is-valid");
    const S2 = this.newConfiguration.S2;
    if (
      newVal < 15 || 
      newVal > 150 || 
      (S2 !== "" && +newVal + 56 === +S2)
    ) {
      ele.classList.add("is-invalid");
    } else {
      ele.classList.add("is-valid");
    }
  },
  "newConfiguration.S2"(newVal) {
    let ele = document.querySelector("#S2");
    ele.classList.remove("is-invalid", "is-valid");
    const S1 = this.newConfiguration.S1;
    if (
      newVal < 15 || 
      newVal > 150 || 
      (S1 !== "" && +S1 + 56 === +newVal)
    ) {
      ele.classList.add("is-invalid");
    } else {
      ele.classList.add("is-valid");
    }
  },
  "newConfiguration.H1"(newVal) {
    this.validateHValues();
  },
  "newConfiguration.H2"(newVal) {
    this.validateHValues();
  },
  "newConfiguration.H3"(newVal) {
    this.validateHValues();
  },
  "newConfiguration.H4"(newVal) {
    this.validateHValues();
  },
  },
};
</script>



<template>
  <div class="mt-md-5 mt-3 text-body">
	<div class="ms-sm-auto d-flex mb-4 gap-2 flex-column">
    
      <!-- Header Section -->
      <div class="mb-4 d-flex align-items-center gap-4">
        <RouterLink to="/" class="btn btn-dark btn-brand p-2 shadow" style="border-radius: 100%">
          <h2 class="mb-0" style="line-height: 0">
            <i class="bi bi-arrow-left-circle"></i>
          </h2>
        </RouterLink>
        <h2 class="flex-column">
          <LocaleText t="New Configuration"></LocaleText>
		 
        </h2>
      </div>

      <!-- Form -->
      <form class="text-body d-flex flex-column gap-3" @submit.prevent="saveNewConfiguration">
		<div class="card rounded-3 shadow">
					<div class="card-header">
						<LocaleText t="Protocol"></LocaleText>
					</div>
					<div class="card-body d-flex gap-2 protocolBtnGroup">
						<a 
							@click="this.newConfiguration.Protocol = 'wg'"
							:class="{'opacity-50': this.newConfiguration.Protocol !== 'wg'}"
							class="btn btn-primary wireguardBg border-0 " style="flex-basis: 100%">
							<i class="bi bi-check-circle-fill me-2" v-if="this.newConfiguration.Protocol === 'wg'"></i>
							<i class="bi bi-circle me-2" v-else></i>
							<strong>
								WireGuard
							</strong>
						</a>
						<a
							@click="this.newConfiguration.Protocol = 'awg'"
							:class="{'opacity-50': this.newConfiguration.Protocol !== 'awg'}"
							class="btn btn-primary amneziawgBg border-0" style="flex-basis: 100%">
							<i class="bi bi-check-circle-fill me-2" v-if="this.newConfiguration.Protocol === 'awg'"></i>
							<i class="bi bi-circle me-2" v-else></i>
							<strong>
								AmneziaWG
							</strong>
						</a>
					</div>
				</div>
        <!-- Configuration Name -->
        <div class="card rounded-3 shadow">
          <div class="card-header">
            <LocaleText t="Configuration Name"></LocaleText>
          </div>
          <div class="card-body">
            <input
              type="text"
              class="form-control"
              placeholder="ex. wg1"
              id="ConfigurationName"
              v-model="newConfiguration.ConfigurationName"
              :disabled="loading"
              required
            />
            <div class="invalid-feedback">
              <div v-if="error">{{ errorMessage }}</div>
              <div v-else>
                <LocaleText t="Configuration name is invalid. Possible reasons:"></LocaleText>
                <ul class="mb-0">
                  <li>
                    <LocaleText t="Configuration name already exists."></LocaleText>
                  </li>
                  <li>
                    <LocaleText t="Configuration name can only contain 15 lower/uppercase alphabet, numbers, underscore, equal sign, plus sign, period, and hyphen."></LocaleText>
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </div>

		<!-- Private/Public Key -->
		<div class="card rounded-3 shadow">
					<div class="card-header">
						<LocaleText t="Private Key"></LocaleText> & <LocaleText t="Public Key"></LocaleText>
					</div>
					<div class="card-body" style="font-family: var(--bs-font-monospace)">
						<div class="mb-2">
							<label class="text-muted fw-bold mb-1"><small>
								<LocaleText t="Private Key"></LocaleText>
							</small></label>
							<div class="input-group">
								<input type="text" class="form-control" id="PrivateKey" 
								       v-model="newConfiguration.PrivateKey" disabled>
								<button class="btn btn-outline-primary" type="button" title="Regenerate Private Key"
								        @click="wireguardGenerateKeypair">
									<i class="bi bi-arrow-repeat"></i>
								</button>
							</div>
						</div>
						<div>
							<label class="text-muted fw-bold mb-1"><small>
								<LocaleText t="Public Key"></LocaleText>
							</small></label>
							<input type="text" class="form-control" id="PublicKey" 
							       v-model="newConfiguration.PublicKey" disabled>
						</div>
					</div>
				</div>

				<!-- Listen Port -->
				<div class="card rounded-3 shadow">
					<div class="card-header">
						<LocaleText t="Listen Port"></LocaleText>
					</div>
					<div class="card-body">
						<input type="number" class="form-control" placeholder="0-65353" id="ListenPort" 
						       v-model="newConfiguration.ListenPort"
						       :disabled="loading"
						       min="1"
						       max="65353"
						       required>
						<div class="invalid-feedback">
							<div v-if="error">{{ errorMessage }}</div>
							<div v-else>
								<LocaleText t="Invalid port"></LocaleText>
							</div>
						</div>
					</div>
				</div>

				<!-- IP Address/CIDR -->
				<div class="card rounded-3 shadow">
					<div class="card-header d-flex align-items-center">
						<LocaleText t="IP Address/CIDR"></LocaleText>
						<span class="badge rounded-pill text-bg-success ms-auto">
							{{ numberOfAvailableIPs }} Available IPs
						</span>
					</div>
					<div class="card-body">
						<input type="text" class="form-control" 
						       placeholder="Ex: 10.0.0.1/24" id="Address" 
						       v-model="newConfiguration.Address"
						       :disabled="loading"
						       required>
						<div class="invalid-feedback">
							<div v-if="error">{{ errorMessage }}</div>
							<div v-else>
								IP Address/CIDR is invalid
							</div>
						</div>
					</div>
				</div>

    <!-- Optional Settings for AmneziaWG Parameters -->
    <div v-if="newConfiguration.Protocol === 'awg'">
      <div class="card rounded-3 shadow">
        <div class="card-header">
          <LocaleText t="AmneziaWG Parameters"></LocaleText>
        </div>
        <div class="card-body">
          <div v-for="key in ['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4']" :key="key" class="mb-3">
            <label class="text-muted fw-bold mb-1"><small>{{ key }}</small></label>
            <div v-if="descriptions[key]" class="form-text text-muted">
              <small>{{ descriptions[key] }}</small>
            </div>
            <input
              type="number"
              class="form-control"
              v-model="newConfiguration[key]"
              :id="key"
              :placeholder="key"
            />
            <div class="invalid-feedback">
              <LocaleText :t="`Invalid value for ${key}`"></LocaleText>
            </div>
            <div class="valid-feedback">
              <LocaleText :t="`Valid value for ${key}`"></LocaleText>
            </div>
          </div>
        </div>
      </div>
    </div>
		<hr>
				<div class="accordion" id="newConfigurationOptionalAccordion">
					<div class="accordion-item">
						<h2 class="accordion-header">
							<button class="accordion-button collapsed" type="button" 
							        data-bs-toggle="collapse" data-bs-target="#newConfigurationOptionalAccordionCollapse">
								<LocaleText t="Optional Settings"></LocaleText>
							</button>
						</h2>
						<div id="newConfigurationOptionalAccordionCollapse" 
						     class="accordion-collapse collapse" data-bs-parent="#newConfigurationOptionalAccordion">
							<div class="accordion-body d-flex flex-column gap-3">
								<!-- Pre/Post Up/Down -->
								<div class="card rounded-3" v-for="field in ['PreUp', 'PreDown', 'PostUp', 'PostDown']" :key="field">
									<div class="card-header">{{ field }}</div>
									<div class="card-body">
										<input type="text" class="form-control" 
										       :id="field.toLowerCase()" 
										       v-model="newConfiguration[field]">
									</div>
								</div>

				
							</div>
						</div>
					</div>
				</div>

        <!-- Submit Button -->
        <button class="btn btn-dark btn-brand rounded-3 px-3 py-2 shadow ms-auto" :disabled="!goodToSubmit || loading || success">
          <span v-if="success" class="d-flex w-100">
            <LocaleText t="Success"></LocaleText>!
            <i class="bi bi-check-circle-fill ms-2"></i>
          </span>
          <span v-else>
            <LocaleText t="Save Configuration"></LocaleText>
          </span>
        </button>
      </form>
    </div>
  </div>
</template>
