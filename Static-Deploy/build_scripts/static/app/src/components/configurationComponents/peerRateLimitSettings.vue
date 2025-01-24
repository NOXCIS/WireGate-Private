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
          <div v-if="error" class="alert alert-danger mb-3 error-message">
            <span class="message-text">{{ error }}</span>
          </div>
          
          <!-- Upload Rate -->
          <div class="mb-3">
            <label class="form-label">
              <LocaleText t="Upload Rate Limit"></LocaleText>
            </label>
            <div v-if="fetchingRate" class="text-center py-3">
              <div class="spinner-border spinner-border-sm" role="status">
                <span class="visually-hidden">Loading...</span>
              </div>
            </div>
            <div v-else class="input-group">
              <input 
                type="number" 
                class="form-control"
                v-model="uploadRateValue"
                min="0"
                :placeholder="'Enter upload rate limit'"
              />
              <button class="btn btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown">
                {{ uploadRateUnit }}/s
              </button>
              <ul class="dropdown-menu dropdown-menu-end">
                <li><a class="dropdown-item" @click="updateUnit('upload', 'KB')">KB/s</a></li>
                <li><a class="dropdown-item" @click="updateUnit('upload', 'MB')">MB/s</a></li>
                <li><a class="dropdown-item" @click="updateUnit('upload', 'GB')">GB/s</a></li>
              </ul>
            </div>
          </div>

          <!-- Download Rate -->
          <div class="mb-3">
            <label class="form-label">
              <LocaleText t="Download Rate Limit"></LocaleText>
            </label>
            <div v-if="fetchingRate" class="text-center py-3">
              <div class="spinner-border spinner-border-sm" role="status">
                <span class="visually-hidden">Loading...</span>
              </div>
            </div>
            <div v-else class="input-group">
              <input 
                type="number" 
                class="form-control"
                v-model="downloadRateValue"
                min="0"
                :placeholder="'Enter download rate limit'"
              />
              <button class="btn btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown">
                {{ downloadRateUnit }}/s
              </button>
              <ul class="dropdown-menu dropdown-menu-end">
                <li><a class="dropdown-item" @click="updateUnit('download', 'KB')">KB/s</a></li>
                <li><a class="dropdown-item" @click="updateUnit('download', 'MB')">MB/s</a></li>
                <li><a class="dropdown-item" @click="updateUnit('download', 'GB')">GB/s</a></li>
              </ul>
            </div>
          </div>

          <small class="text-muted d-block mt-1">
            <LocaleText t="Enter 0 to remove rate limit"></LocaleText>
          </small>
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
import { DashboardConfigurationStore } from "@/stores/DashboardConfigurationStore.js"

export default {
  name: "PeerRateLimitSettings",
  components: {
    LocaleText
  },
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
  setup() {
    const dashboardStore = DashboardConfigurationStore()
    return { dashboardStore }
  },
  data() {
    return {
      uploadRateValue: 0,
      uploadRateUnit: 'KB',
      downloadRateValue: 0,
      downloadRateUnit: 'KB',
      loading: false,
      error: null,
      isRemoving: false,
      fetchingRate: false,
    }
  },
  async created() {
    await this.fetchExistingRateLimit();
  },
  computed: {
    isValidRate() {
      const uploadRate = parseFloat(this.uploadRateValue);
      const downloadRate = parseFloat(this.downloadRateValue);
      return !isNaN(uploadRate) && !isNaN(downloadRate) && uploadRate >= 0 && downloadRate >= 0;
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
      this.error = null;
      
      try {
        await fetchGet("/api/get_peer_rate_limit", {
          interface: this.configurationInfo.Name,
          peer_key: this.selectedPeer.id
        }, (response) => {
          console.log('Raw API Response:', response);
          
          if (!response?.status) {
            throw new Error(response?.message || 'Failed to fetch rate limits');
          }

          const uploadRateKb = response.data?.upload_rate ?? 0;
          const downloadRateKb = response.data?.download_rate ?? 0;
          
          [this.uploadRateValue, this.uploadRateUnit] = this.convertFromKb(uploadRateKb);
          [this.downloadRateValue, this.downloadRateUnit] = this.convertFromKb(downloadRateKb);
        });
      } catch (error) {
        console.error('Fetch error:', error);
        this.error = error.message || 'Failed to fetch rate limits';
        this.uploadRateValue = 0;
        this.uploadRateUnit = 'KB';
        this.downloadRateValue = 0;
        this.downloadRateUnit = 'KB';
      } finally {
        this.fetchingRate = false;
      }
    },
    
    async applyRateLimit() {
      if (!this.isValidRate) return;
      
      this.loading = true;
      this.error = null;
      this.isRemoving = false;
      
      const uploadRateKb = this.convertToKb(this.uploadRateValue, this.uploadRateUnit);
      const downloadRateKb = this.convertToKb(this.downloadRateValue, this.downloadRateUnit);
      
      try {
        await fetchPost("/api/set_peer_rate_limit", {
          interface: this.configurationInfo.Name,
          peer_key: this.selectedPeer.id,
          upload_rate: uploadRateKb,
          download_rate: downloadRateKb
        }, (response) => {
          if (response && response.success) {
            this.dashboardStore.newMessage('Server', 'Rate limits set successfully', 'success');
            this.$emit('refresh');
            this.$emit('close');
          } else {
            this.dashboardStore.newMessage('Error', response?.message || 'Failed to set rate limits', 'danger');
          }
        });
      } catch (error) {
        console.error('Request error:', error);
        this.dashboardStore.newMessage('Error', 'Network error while setting rate limits', 'danger');
        this.error = 'Network error while setting rate limits';
      } finally {
        this.loading = false;
      }
    },
    
    async removeRateLimit() {
      this.loading = true;
      this.error = null;
      this.isRemoving = true;
      
      try {
        await fetchPost("/api/remove_peer_rate_limit", {
          interface: this.configurationInfo.Name,
          peer_key: this.selectedPeer.id
        }, (response) => {
          if (response && response.status) {
            this.dashboardStore.newMessage('Server', 'Rate limit removed successfully', 'success');
            this.$emit('refresh');
            this.$emit('close');
          } else {
            this.dashboardStore.newMessage('Error', response?.message || 'Failed to remove rate limit', 'danger');
          }
        });
      } catch (error) {
        console.error("Failed to remove rate limit:", error);
        this.dashboardStore.newMessage('Error', 'Network error while removing rate limit', 'danger');
        this.error = 'Network error while removing rate limit';
      } finally {
        this.loading = false;
        this.isRemoving = false;
      }
    },
    
    convertFromKb(rateInKb) {
      if (rateInKb >= 1024 * 1024) {
        return [(rateInKb / (1024 * 1024)).toFixed(2), 'GB'];
      } else if (rateInKb >= 1024) {
        return [(rateInKb / 1024).toFixed(2), 'MB'];
      }
      return [rateInKb, 'KB'];
    },
    
    updateUnit(direction, newUnit) {
      const value = direction === 'upload' ? this.uploadRateValue : this.downloadRateValue;
      const currentUnit = direction === 'upload' ? this.uploadRateUnit : this.downloadRateUnit;
      
      if (value) {
        // Convert current value to KB first
        const valueInKb = this.convertToKb(value, currentUnit);
        
        // Convert KB to the new unit
        let newValue;
        switch (newUnit) {
          case 'GB':
            newValue = (valueInKb / (1024 * 1024)).toFixed(2);
            break;
          case 'MB':
            newValue = (valueInKb / 1024).toFixed(2);
            break;
          case 'KB':
            newValue = valueInKb;
            break;
        }
        
        // Update the appropriate direction
        if (direction === 'upload') {
          this.uploadRateValue = newValue;
          this.uploadRateUnit = newUnit;
        } else {
          this.downloadRateValue = newValue;
          this.downloadRateUnit = newUnit;
        }
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
.error-message {
  word-wrap: break-word;
  word-break: break-word;
  white-space: pre-wrap;
  max-width: 100%;
  overflow-wrap: break-word;
  overflow: hidden;
  text-overflow: ellipsis;
  display: block;
  padding: 0.75rem 1.25rem;
  margin: 1rem 0;
  border-radius: 0.25rem;
}
.message-text {
  display: inline-block;
  word-break: break-all;
  white-space: normal;
  width: 100%;
}
</style> 