<script>
import { parse } from "cidr-tools";
import "@/utilities/wireguard.js";
import { WireguardConfigurationsStore } from "@/stores/WireguardConfigurationsStore.js";
import { fetchPost } from "@/utilities/fetch.js";
import LocaleText from "@/components/text/localeText.vue";
import { generateTorIPTables, generateTorIPTablesTeardown, generatePlainIPTables, generatePlainIPTablesTeardown } from "@/utilities/iptablesConfig.js";
import {parseInterface, parsePeers} from "@/utilities/parseConfigurationFile.js";
import {DashboardConfigurationStore} from "@/stores/DashboardConfigurationStore.js";

export default {
  name: "newConfiguration",
  components: { LocaleText },
  async setup(){
		const store = WireguardConfigurationsStore()
		//const protocols = ref([])
		//await fetchGet("/api/protocolsEnabled", {}, (res) => {
		//	protocols.value = res.data
		//})
		const dashboardStore = DashboardConfigurationStore();
		
		return {store, dashboardStore}
	},
  data() {
    return {
      isAWGOpen: false,
      selectedField: null,
      iptablesEnabled: false,
      newConfiguration: {
        ConfigurationName: "",
        Address: "",
        ListenPort: "",
        PrivateKey: "",
        PublicKey: "",
        PresharedKey: "",
        iptablesEnabled: false,
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
      previousIPTables: {
      PostUp: "",
      PreDown: "",
    },
    hasUnsavedChanges: false,
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
      parseInterfaceResult: undefined,
			parsePeersResult: undefined
    };
  },
  created() {
    this.wireguardGenerateKeypair();
  this.generateRandomValues();
  
  // Only set default IPTables scripts for brand new configurations
  if (!this.newConfiguration.PostUp && !this.newConfiguration.PreDown) {
    this.newConfiguration.PostUp = generatePlainIPTables(this.newConfiguration);
    this.newConfiguration.PreDown = generatePlainIPTablesTeardown(this.newConfiguration);
  }
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
      
      let uniqueHValues = new Set(hValues.filter((v) => v !== '' && v >= 5 && v <= 2147483647));
      let isValid = hValues.length === uniqueHValues.size && uniqueHValues.size === 4;

      hValues.forEach((value, index) => {
        const ele = document.querySelector(`#H${index + 1}`);
        if (!ele) return;

        ele.classList.remove("is-invalid", "is-valid");
        
        if (
          value === '' || 
          !isValid || 
          value < 5 || 
          value > 2147483647
        ) {
          ele.classList.add("is-invalid");
        } else {
          ele.classList.add("is-valid");
        }
      });
    },
    validateListenPort(event) {
      const value = event.target.value;
      const ele = event.target;
      ele.classList.remove("is-invalid", "is-valid");
      
      if (value === "" || value < 0 || value > 65353 || !Number.isInteger(+value)) {
        ele.classList.add("is-invalid");
      } else {
        ele.classList.add("is-valid");
      }
    },

    //good
    // Toggle method now switches between Tor and plain IPTables
    toggleIPTables() {
    // Store current scripts before toggling
    this.previousIPTables = {
      PostUp: this.newConfiguration.PostUp,
      PreDown: this.newConfiguration.PreDown
    };

    this.iptablesEnabled = !this.iptablesEnabled;
    this.updateIPTablesScripts();
    this.hasUnsavedChanges = true;
  },

  // Add new revertIPTables method
  revertIPTables() {
    // Restore previous scripts
    this.newConfiguration.PostUp = this.previousIPTables.PostUp;
    this.newConfiguration.PreDown = this.previousIPTables.PreDown;
    
    // Reset toggle state to match previous configuration
    this.iptablesEnabled = this.newConfiguration.PostUp.includes("iptables -t nat -A POSTROUTING");
    
    // Clear previous state and unsaved changes flag
    this.previousIPTables = {
      PostUp: "",
      PreDown: ""
    };
    this.hasUnsavedChanges = false;
  },

  // Update the existing updateIPTablesScripts method
  updateIPTablesScripts() {
    if (this.iptablesEnabled) {
      // When Tor mode is enabled
      this.newConfiguration.PostUp = generateTorIPTables(this.newConfiguration);
      this.newConfiguration.PreDown = generateTorIPTablesTeardown(this.newConfiguration);
    } else {
      // Switch back to plain IPTables
      this.newConfiguration.PostUp = generatePlainIPTables(this.newConfiguration);
      this.newConfiguration.PreDown = generatePlainIPTablesTeardown(this.newConfiguration);
    }
    this.hasUnsavedChanges = true;
  },

  // Add method to check if scripts have changed
  haveScriptsChanged() {
    return this.previousIPTables.PostUp !== this.newConfiguration.PostUp ||
           this.previousIPTables.PreDown !== this.newConfiguration.PreDown;
  },






    openFileUpload(){
			document.querySelector("#fileUpload").click();
		},
		readFile(e) {
  const file = e.target.files[0];
  if (!file) return false;
  
  const reader = new FileReader();
  reader.onload = (evt) => {
    const fileContent = evt.target.result;
    const parsedInterface = parseInterface(fileContent);
    
    if (parsedInterface) {
      // Set basic configuration
      this.newConfiguration = {
        ...this.newConfiguration,
        ConfigurationName: file.name.replace('.conf', ''),
        Protocol: parsedInterface.Protocol || 'wg',
        
        // IPTables scripts - always set these regardless of content
        PreUp: parsedInterface.PreUp || '',
        PostUp: parsedInterface.PostUp || '',
        PreDown: parsedInterface.PreDown || '',
        PostDown: parsedInterface.PostDown || '',
        
        // Other fields
        Address: parsedInterface.Address || '',
        ListenPort: parsedInterface.ListenPort?.toString() || '',
        PrivateKey: parsedInterface.PrivateKey || '',
        PublicKey: parsedInterface.PublicKey || '',
        PresharedKey: parsedInterface.PresharedKey || ''
      };

      // Handle AmneziaWG specific parameters if present
      if (parsedInterface.Protocol === 'awg') {
        this.isAWGOpen = true;
        const awgParams = ['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4'];
        awgParams.forEach(param => {
          this.newConfiguration[param] = parsedInterface[param] || '';
        });
      }

      // If any IPTables scripts exist, show them in the UI
      const hasIptablesContent = parsedInterface.PreUp || 
                                parsedInterface.PostUp || 
                                parsedInterface.PreDown || 
                                parsedInterface.PostDown;

      if (hasIptablesContent) {
        this.$nextTick(() => {
          // Open the IPTables accordion
          const accordion = document.querySelector('#newConfigurationOptionalAccordionCollapse');
          if (accordion) {
            accordion.classList.add('show');
            
            const button = document.querySelector('[data-bs-target="#newConfigurationOptionalAccordionCollapse"]');
            if (button) {
              button.classList.remove('collapsed');
              button.setAttribute('aria-expanded', 'true');
            }

            // Select the first non-empty IPTables field
            ['PreUp', 'PostUp', 'PreDown', 'PostDown'].some(field => {
              if (parsedInterface[field]) {
                this.selectedField = field;
                return true;
              }
              return false;
            });
          }
        });
      }

      // Reset iptablesEnabled to false since it's independent of uploaded configs
      this.iptablesEnabled = false;

      // Validate all fields after setting them
      this.$nextTick(() => {
        // Validate standard fields
        ['ListenPort', 'Address', 'PrivateKey'].forEach(field => {
          const input = document.querySelector(`#${field}`);
          if (input) {
            input.dispatchEvent(new Event('input'));
          }
        });

        // Validate AmneziaWG fields if needed
        if (this.newConfiguration.Protocol === 'awg') {
          ['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4'].forEach(field => {
            const input = document.querySelector(`#${field}`);
            if (input) {
              input.dispatchEvent(new Event('input'));
            }
          });
          this.validateHValues();
        }
      });

      // Show success message
      this.dashboardStore.newMessage(
        "WireGate",
        `Configuration file uploaded successfully`,
        "success"
      );
    } else {
      this.dashboardStore.newMessage(
        "WireGate",
        "Failed to upload configuration file",
        "danger"
      );
    }
  };
  reader.readAsText(file);
    },
    validateParameters() {
      this.resetValidation();
      let isValid = true;

      // Validate Configuration Name
      const configNameElement = document.querySelector("#ConfigurationName");
      if (configNameElement) {
        if (!this.newConfiguration.ConfigurationName || 
            !/^[a-zA-Z0-9_=+.-]{1,15}$/.test(this.newConfiguration.ConfigurationName) ||
            this.store.Configurations.find((x) => x.Name === this.newConfiguration.ConfigurationName)) {
          configNameElement.classList.add("is-invalid");
          isValid = false;
        } else {
          configNameElement.classList.add("is-valid");
        }
      }

      // Validate Address
      const addressElement = document.querySelector("#Address");
      if (addressElement) {
        try {
          if (!this.newConfiguration.Address || 
              this.newConfiguration.Address.trim().split("/").filter((x) => x.length > 0).length !== 2) {
            throw new Error();
          }
          parse(this.newConfiguration.Address);
          addressElement.classList.add("is-valid");
        } catch (e) {
          addressElement.classList.add("is-invalid");
          isValid = false;
        }
      }

      // Validate Listen Port
      const portElement = document.querySelector("#ListenPort");
      if (portElement) {
        const port = this.newConfiguration.ListenPort;
        if (port === "" || port < 0 || port > 65353 || !Number.isInteger(+port)) {
          portElement.classList.add("is-invalid");
          isValid = false;
        } else {
          portElement.classList.add("is-valid");
        }
      }

      return isValid;
    },
    resetValidation() {
      const fields = ['ConfigurationName', 'Address', 'ListenPort'];
      fields.forEach(field => {
        const element = document.querySelector(`#${field}`);
        if (element) {
          element.classList.remove('is-invalid', 'is-valid');
        }
      });
      this.error = false;
      this.errorMessage = "";
    },
    async saveNewConfiguration() {
      if (this.validateParameters() && this.goodToSubmit) {
        this.loading = true;
        const apiData = this.prepareApiData();
        
        try {
          await fetchPost("/api/addWireguardConfiguration", apiData, async (res) => {
            if (res.status) {
              this.success = true;
              await this.store.getConfigurations();
              this.$router.push(`/configuration/${this.newConfiguration.ConfigurationName}/peers`);
            } else {
              this.error = true;
              this.errorMessage = res.message;
              
              // Handle specific field errors
              if (res.data) {
                const errorField = document.querySelector(`#${res.data}`);
                if (errorField) {
                  errorField.classList.remove("is-valid");
                  errorField.classList.add("is-invalid");
                  
                  // Reset validation state after error
                  this.$nextTick(() => {
                    // Re-enable form interaction
                    this.loading = false;
                    
                    // Add event listeners to clear error state on input
                    errorField.addEventListener('input', () => {
                      errorField.classList.remove('is-invalid');
                      this.error = false;
                      this.errorMessage = "";
                    }, { once: true });
                  });
                }
              }
            }
          });
        } catch (error) {
          this.error = true;
          this.errorMessage = "An error occurred while saving the configuration. Please try again.";
          this.loading = false;
        }
        
        if (!this.success) {
          this.loading = false;
        }
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
        PreDown: this.iptablesEnabled ? PreDown : "",
        PostUp: this.iptablesEnabled ? PostUp : "",
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
    'newConfiguration.PostUp'(newVal, oldVal) {
    if (oldVal && newVal !== oldVal) {
      this.hasUnsavedChanges = true;
    }
  },
  'newConfiguration.PreDown'(newVal, oldVal) {
    if (oldVal && newVal !== oldVal) {
      this.hasUnsavedChanges = true;
    }
  },
    //good
		'newConfiguration.ConfigurationName'(newVal){
			
			let ele = document.querySelector("#ConfigurationName");
			ele.classList.remove("is-invalid", "is-valid")
			if (!/^[a-zA-Z0-9_=+.-]{1,15}$/.test(newVal) || newVal.length === 0 || this.store.Configurations.find(x => x.Name === newVal)){
				ele.classList.add("is-invalid")
			}else{
				ele.classList.add("is-valid")
			}
		},
    //good
		"newConfiguration.Address"(newVal) {
      const ele = document.querySelector("#Address");
      if (!ele) return;

      ele.classList.remove("is-invalid", "is-valid");
      try {
        if (!newVal || newVal.trim().split("/").filter((x) => x.length > 0).length !== 2) {
          throw new Error();
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
    //good
    "newConfiguration.ListenPort"(newVal) {
      const ele = document.querySelector("#ListenPort");
      if (!ele) return;

      ele.classList.remove("is-invalid", "is-valid");

      if (newVal === "" || newVal < 0 || newVal > 65353 || !Number.isInteger(+newVal)) {
        ele.classList.add("is-invalid");
      } else {
        ele.classList.add("is-valid");
      }
    },
    //good
    "newConfiguration.PrivateKey": {
      handler(newVal) {
        if (newVal && window.wireguard) {
          try {
            this.newConfiguration.PublicKey = window.wireguard.generatePublicKey(newVal);
          } catch (e) {
            console.error('Error generating public key:', e);
          }
        }
      }
    },

    
    "newConfiguration.Jc"(newVal) {
      const ele = document.querySelector("#Jc");
      if (!ele) return;

      ele.classList.remove("is-invalid", "is-valid");
      if (newVal === "" || newVal < 1 || newVal > 128 || !Number.isInteger(+newVal)) {
        ele.classList.add("is-invalid");
      } else {
        ele.classList.add("is-valid");
      }
    },
    "newConfiguration.Jmin"(newVal) {
      const ele = document.querySelector("#Jmin");
      if (!ele) return;

      ele.classList.remove("is-invalid", "is-valid");
      const Jmax = this.newConfiguration.Jmax;
      if (
        newVal === "" ||
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
      const ele = document.querySelector("#Jmax");
      if (!ele) return;

      ele.classList.remove("is-invalid", "is-valid");
      const Jmin = this.newConfiguration.Jmin;
      if (
        newVal === "" ||
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
      const ele = document.querySelector("#S1");
      if (!ele) return;

      ele.classList.remove("is-invalid", "is-valid");
      const S2 = this.newConfiguration.S2;
      if (
        newVal === "" ||
        newVal < 15 || 
        newVal > 150 || 
        (S2 !== "" && +newVal + 56 === +S2)
      ) {
        ele.classList.add("is-invalid");
      } else {
        ele.classList.add("is-valid");
      }
    },
    //new fix
    "newConfiguration.S2"(newVal) {
      const ele = document.querySelector("#S2");
      if (!ele) return;

      ele.classList.remove("is-invalid", "is-valid");
      const S1 = this.newConfiguration.S1;
      if (
        newVal === "" ||
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
mounted() {
		const fileUpload = document.querySelector("#fileUpload");
		fileUpload.addEventListener("change", this.readFile, false)
	}
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
        <div class="d-flex gap-2 ms-auto">
					<button class="titleBtn py-2 text-decoration-none btn text-primary-emphasis bg-primary-subtle rounded-3 border-1 border-primary-subtle"
					        @click="openFileUpload()"
					        type="button" aria-expanded="false">
						<i class="bi bi-upload me-2"></i>
						<LocaleText t="Upload File"></LocaleText>
					</button>
					<input type="file" id="fileUpload" multiple class="d-none" accept=".conf" />
				</div>
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
    class="btn btn-primary wireguardBg border-0" style="flex-basis: 100%">
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
  <a
    @click="toggleIPTables"
    :class="{
      'btn-success': iptablesEnabled, 
      'btn-secondary': !iptablesEnabled,
      'opacity-50': !iptablesEnabled
    }"
    class="btn border-0 torBg d-flex align-items-center justify-content-center position-relative" 
    style="flex-basis: 100%"
  >
    <i class="bi bi-check-circle-fill me-2" v-if="iptablesEnabled"></i>
    <i class="bi bi-circle me-2" v-else></i>
    <strong class="d-flex align-items-center">
      <img 
        src="https://gitlab.torproject.org/tpo/web/styleguide/-/raw/d857504c03c6e3d04b427a49a6c5eb0383cfd25c/assets/static/images/tor-logo/white.svg"
        class="me-2"
        alt="Tor Logo"
        style="width: 30px; height: 20px;"
      >
    </strong>
    
    <!-- New revert button -->
    <button 
      v-if="hasUnsavedChanges"
      @click.stop="revertIPTables"
      class="btn btn-warning btn-sm position-absolute"
      style="right: -10px; top: -10px;"
      title="Revert IPTables changes"
    >
      <i class="bi bi-arrow-counterclockwise"></i>
    </button>
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

		<!-- Listen Port Section -->
    <div class="card rounded-3 shadow">
    <div class="card-header">
      <LocaleText t="Listen Port"></LocaleText>
    </div>
    <div class="card-body">
      <input 
        type="number" 
        class="form-control" 
        placeholder="0-65353" 
        id="ListenPort" 
        v-model.number="newConfiguration.ListenPort"
        :disabled="loading"
        min="1"
        max="65353"
        @input="validateListenPort"
        required
      >
      <div class="invalid-feedback">
        <div v-if="error">{{ errorMessage }}</div>
        <div v-else>
          <LocaleText t="Invalid port"></LocaleText>
        </div>
      </div>
    </div>
  </div>

  <!-- Private/Public Key Section -->
  <div class="card rounded-3 shadow">
      <div class="card-header">
        <LocaleText t="Private Key"></LocaleText> & <LocaleText t="Public Key"></LocaleText>
      </div>
      <div class="card-body" style="font-family: var(--bs-font-monospace)">
        <div class="mb-2">
          <label class="text-muted fw-bold mb-1">
            <small><LocaleText t="Private Key"></LocaleText></small>
          </label>
          <div class="input-group">
            <input 
              type="text" 
              class="form-control" 
              id="PrivateKey" 
              v-model="newConfiguration.PrivateKey" 
              :disabled="loading"
            >
            <button 
              class="btn btn-outline-primary" 
              type="button" 
              title="Regenerate Private Key"
              @click="wireguardGenerateKeypair"
              :disabled="loading"
            >
              <i class="bi bi-arrow-repeat"></i>
            </button>
          </div>
        </div>
        <div>
          <label class="text-muted fw-bold mb-1">
            <small><LocaleText t="Public Key"></LocaleText></small>
          </label>
          <input 
            type="text" 
            class="form-control" 
            id="PublicKey" 
            v-model="newConfiguration.PublicKey"
            disabled
          >
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
      <div class="card shadow" :class="{'rounded-3': isAWGOpen, 'rounded-pill': !isAWGOpen}">
        <div 
          @click="isAWGOpen = !isAWGOpen" 
          class="card-header awg-header fw-bold d-flex justify-content-between align-items-center cursor-pointer"
          :class="{'rounded-3': !isAWGOpen}"
        >
          <LocaleText t="AmneziaWG Parameters"></LocaleText>
          <i :class="['bi', isAWGOpen ? 'bi-chevron-up' : 'bi-chevron-down']"></i>
        </div>
        
        <div v-show="isAWGOpen" class="card-body">
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
        <LocaleText t="IPTables Settings"></LocaleText>
      </button>
    </h2>
    <div id="newConfigurationOptionalAccordionCollapse" 
         class="accordion-collapse collapse" data-bs-parent="#newConfigurationOptionalAccordion">
      <div class="accordion-body">
        <!-- New header section with buttons and unsaved changes indicator -->
    <div class="d-flex justify-content-between align-items-center mb-3">
      <div class="d-flex gap-2 flex-wrap">
        <a v-for="field in ['PreUp', 'PreDown', 'PostUp', 'PostDown']" 
           :key="field"
           class="btn"
           :class="selectedField === field ? 'btn-primary' : 'btn-outline-secondary'"
           @click.prevent="selectedField = field"
           href="#"
           role="button">
          {{ field }}
        </a>
      </div>
      
      <!-- New unsaved changes indicator -->
      <span v-if="hasUnsavedChanges" class="badge bg-warning">
        <i class="bi bi-exclamation-triangle me-1"></i>
        Unsaved Changes
      </span>
        </div>
        
        <!-- Editor Card -->
        <div v-if="selectedField" class="card rounded-3 shadow">
          <div class="card-header d-flex align-items-center justify-content-between">
            <span>{{ selectedField }}</span>
            <a href="#" 
               class="btn btn-sm btn-outline-secondary" 
               @click.prevent="selectedField = null">
              <i class="bi bi-x-lg"></i>
            </a>
          </div>
          <div class="card-body p-0">
            <textarea
              :id="selectedField.toLowerCase()"
              v-model="newConfiguration[selectedField]"
              class="form-control border-0 font-monospace"
              :placeholder="`Enter ${selectedField} commands...`"
              rows="12"
              style="resize: vertical; border-radius: 0 0 0.5rem 0.5rem;"
              spellcheck="false"
              :disabled="loading"
            ></textarea>
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