<template>
  <div class="modal fade show" style="display: block">
    <div class="modal-dialog">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title">
            <LocaleText t="Rate Limit Settings"></LocaleText>
          </h5>
          <button type="button" class="btn-close" @click="$emit('close')"></button>
        </div>
        <div class="modal-body">
          <div v-if="error" class="alert alert-danger mb-3">
            {{ error }}
          </div>
          <div class="mb-3">
            <label class="form-label">
              <LocaleText t="Rate Limit"></LocaleText>
            </label>
            <div v-if="fetchingRate" class="text-center py-3">
              <div class="spinner-border spinner-border-sm" role="status">
                <span class="visually-hidden">Loading...</span>
              </div>
              <span class="ms-2">Loading current rate limit...</span>
            </div>
            <div v-else class="input-group">
              <input 
                type="number" 
                class="form-control"
                v-model="rateValue"
                min="0"
                :placeholder="'Enter rate limit'"
              />
              <button class="btn btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown">
                {{ rateUnit }}/s
              </button>
              <ul class="dropdown-menu dropdown-menu-end">
                <li><a class="dropdown-item" @click="rateUnit = 'KB'">KB/s</a></li>
                <li><a class="dropdown-item" @click="rateUnit = 'MB'">MB/s</a></li>
                <li><a class="dropdown-item" @click="rateUnit = 'GB'">GB/s</a></li>
              </ul>
            </div>
            <small class="text-muted d-block mt-1">
              <LocaleText t="Enter 0 to remove rate limit"></LocaleText>
            </small>
            <small class="text-muted d-block mt-1" v-if="rateValue > 0">
              ≈ {{ formatToKb(rateValue, rateUnit) }} KB/s
            </small>
          </div>
        </div>
        <div class="modal-footer">
          <button 
            class="btn btn-secondary"
            @click="removeRateLimit"
            :disabled="loading"
          >
            <span v-if="loading && isRemoving" class="spinner-border spinner-border-sm me-2"></span>
            <LocaleText t="Remove Limit"></LocaleText>
          </button>
          <button 
            class="btn btn-primary"
            @click="applyRateLimit"
            :disabled="loading || !isValidRate"
          >
            <span v-if="loading && !isRemoving" class="spinner-border spinner-border-sm me-2"></span>
            <LocaleText t="Apply"></LocaleText>
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import LocaleText from "@/components/text/localeText.vue";
import {fetchPost, fetchGet} from "@/utilities/fetch.js";

export default {
  name: "PeerRateLimitSettings",
  components: {LocaleText},
  props: {
    selectedPeer: {
      type: Object,
      required: true
    },
    configurationInfo: {
      type: Object,
      required: true
    }
  },
  data() {
    return {
      rateValue: 0,
      rateUnit: 'KB',
      loading: false,
      error: null,
      isRemoving: false,
      fetchingRate: false
    }
  },
  async created() {
    await this.fetchExistingRateLimit();
  },
  computed: {
    isValidRate() {
      const rate = parseFloat(this.rateValue);
      return !isNaN(rate) && rate >= 0;
    }
  },
  methods: {
    formatToKb(value, unit) {
      const val = parseFloat(value);
      if (isNaN(val)) return '0';
      
      switch (unit) {
        case 'GB':
          return (val * 1024 * 1024).toLocaleString();
        case 'MB':
          return (val * 1024).toLocaleString();
        default:
          return val.toLocaleString();
      }
    },
    
    convertToKb(value, unit) {
      const val = parseFloat(value);
      if (isNaN(val)) return 0;
      
      switch (unit) {
        case 'GB':
          return Math.round(val * 1024 * 1024);
        case 'MB':
          return Math.round(val * 1024);
        default:
          return Math.round(val);
      }
    },
    
    async fetchExistingRateLimit() {
      this.fetchingRate = true;
      console.log('Starting rate limit fetch for:', {
        interface: this.configurationInfo.Name,
        peer_key: this.selectedPeer.id
      });
      
      try {
        const encodedPeerKey = encodeURIComponent(this.selectedPeer.id);
        
        const response = await fetchGet(`/api/get_peer_rate_limit`, {
          interface: this.configurationInfo.Name,
          peer_key: encodedPeerKey
        });
        
        console.log('Rate limit API response:', response);

        if (response && response.rate !== undefined) {
          const rate = parseInt(response.rate);
          console.log('Parsed rate value:', rate);
          
          if (rate >= 1024 * 1024) { // GB
            this.rateValue = (rate / (1024 * 1024)).toFixed(2);
            this.rateUnit = 'GB';
            console.log('Converted to GB:', this.rateValue);
          } else if (rate >= 1024) { // MB
            this.rateValue = (rate / 1024).toFixed(2);
            this.rateUnit = 'MB';
            console.log('Converted to MB:', this.rateValue);
          } else { // KB
            this.rateValue = rate;
            this.rateUnit = 'KB';
            console.log('Kept as KB:', this.rateValue);
          }
          
          console.log('Final rate limit values:', {
            value: this.rateValue,
            unit: this.rateUnit
          });
        } else {
          console.warn('Invalid or missing rate in response:', response);
        }
      } catch (error) {
        console.error('Failed to fetch rate limit:', error);
        console.error('Error details:', {
          name: error.name,
          message: error.message,
          stack: error.stack
        });
        this.error = 'Failed to fetch current rate limit';
      } finally {
        this.fetchingRate = false;
        console.log('Rate limit fetch completed');
      }
    },
    
    async applyRateLimit() {
      if (!this.isValidRate) return;
      
      console.log('Starting rate limit application...');
      this.loading = true;
      this.error = null;
      this.isRemoving = false;
      
      const rateInKb = this.convertToKb(this.rateValue, this.rateUnit);
      console.log('Converted rate:', {
        originalValue: this.rateValue,
        originalUnit: this.rateUnit,
        convertedRateKb: rateInKb
      });
      
      try {
        await fetchPost("/api/set_peer_rate_limit", {
          interface: this.configurationInfo.Name,
          peer_key: this.selectedPeer.id,
          rate: rateInKb
        }, (response) => {
          console.log('API Response:', response);

          if (response && response.success) {
            console.log('Rate limit set successfully');
            this.$emit('refresh');
            this.$emit('close');
          } else {
            console.warn('API returned error:', response?.message);
            this.error = response?.message || 'Failed to set rate limit';
          }
        });
      } catch (error) {
        console.error('Request error:', error);
        this.error = 'Network error while setting rate limit';
      } finally {
        this.loading = false;
      }
    },
    
    async removeRateLimit() {
      this.loading = true;
      this.error = null;
      this.isRemoving = true;
      
      try {
        const response = await fetchPost("/api/remove_peer_rate_limit", {
          interface: this.configurationInfo.Name,
          peer_key: this.selectedPeer.id
        });
        
        if (response.status) {
          this.$emit('refresh');
          this.$emit('close');
        } else {
          this.error = response.message || 'Failed to remove rate limit';
        }
      } catch (error) {
        this.error = 'Network error while removing rate limit';
        console.error("Failed to remove rate limit:", error);
      } finally {
        this.loading = false;
      }
    }
  }
}
</script>

<style scoped>
.modal {
  background: rgba(0, 0, 0, 0.5);
}
.form-select {
  flex: 0 0 auto;
}
</style> 