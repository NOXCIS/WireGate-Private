<!-- IPTablesEditor.vue -->
<script setup>
import { ref, reactive } from 'vue';
import LocaleText from "@/components/text/localeText.vue";

const props = defineProps({
  modelValue: {
    type: Object,
    required: true
  },
  saving: {
    type: Boolean,
    default: false
  }
});

const emit = defineEmits(['update:modelValue']);
const selectedField = ref(null);
const hasUnsavedChanges = ref(false);

// Handle textarea input
const updateField = (field, event) => {
  console.log('Updating field:', field, 'with value:', event.target.value);
  
  const updatedValue = {
    ...props.modelValue,
    [field]: event.target.value
  };
  
  emit('update:modelValue', updatedValue);
  hasUnsavedChanges.value = true;
};
</script>

<template>
  <div class="accordion-body">
    <!-- Header section with buttons and unsaved changes indicator -->
    <div class="d-flex justify-content-between align-items-center mb-3">
      <div class="d-flex gap-2 flex-wrap">
        <a
          v-for="field in ['PreUp', 'PreDown', 'PostUp', 'PostDown']"
          :key="field"
          class="btn bg-primary-subtle border-primary-subtle"
          :class="selectedField === field ? 'btn-primary' : 'btn-outline-secondary'"
          @click.prevent="selectedField = field"
          href="#"
          role="button"
        >
          {{ field }}
        </a>
      </div>
      <span v-if="hasUnsavedChanges" class="badge bg-warning">
        <i class="bi bi-exclamation-triangle me-1"></i>
        Unsaved Changes
      </span>
    </div>

    <!-- Editor Card -->
    <div v-if="selectedField" class="card rounded-3 shadow">
      <div class="card-header d-flex align-items-center justify-content-between">
        <span>{{ selectedField }}</span>
        <button
          type="button"
          class="btn btn-sm btn-warning"
          @click.prevent="selectedField = null"
        >
          <i class="bi bi-x-lg"></i>
        </button>
      </div>
      <div class="script-box p-0">
        <textarea
          :id="selectedField.toLowerCase()"
          :value="modelValue[selectedField]"
          @input="updateField(selectedField, $event)"
          class="form-control script-box-active border-0 form-control-sm font-monospace resizable-textarea"
          :placeholder="`Enter ${selectedField} commands...`"
          rows="12"
          spellcheck="false"
          :disabled="saving"
        ></textarea>
      </div>
    </div>
  </div>
</template>

<style scoped>
.script-box {
  position: relative;
  min-height: 100px;
}

.resizable-textarea {
  resize: vertical;
  overflow: scroll;
  min-height: 500px;
  max-height: 1000px;
  width: 100%;
  background-color: #212529;
  color: #fff;
  padding: 0.5rem;
}

/* Scrollbar styling */
.resizable-textarea::-webkit-scrollbar {
  width: 8px;
  height: 8px;
}

.resizable-textarea::-webkit-scrollbar-track {
  background: #5c5c5c;
}

.resizable-textarea::-webkit-scrollbar-thumb {
  background: #888;
  border-radius: 4px;
}

.resizable-textarea::-webkit-scrollbar-thumb:hover {
  background: #555;
}

/* Ensures the resize handle is visible */
.resizable-textarea::-webkit-resizer {
  border-width: 8px;
  border-style: solid;
  border-color: transparent #6c757d #6c757d transparent;
}
</style>