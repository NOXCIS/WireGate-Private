<script>
export default {
  name: 'WeeklySchedule',
  props: {
    edit: {
      type: Boolean,
      default: false
    },
    weeklyOptions: {
      type: Array,
      required: true
    },
    selectedDays: {
      type: Array,
      required: true
    },
    timeIntervals: {
      type: Object,
      required: true
    }
  },
  methods: {
    toggleDay(day) {
      if (!this.edit) return;
      this.$emit('update:toggle-day', day);
    },
    updateTimeInterval(day, type, value) {
      // Validate time format
      const timeRegex = /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/;
      if (!timeRegex.test(value)) {
        console.warn('Invalid time format:', value);
        return;
      }

      if (this.timeIntervals[day]) {
        this.timeIntervals[day][type] = value;
        this.$emit('update:time-interval', day, type, value);
      }
    },
    updateTimeFromSlider(day, type, value) {
      const timeString = this.minutesToTime(parseInt(value));
      this.timeIntervals[day][type] = timeString;
      this.$emit('update:time-interval', { day, type, value: timeString });
    },
    timeToMinutes(time) {
      if (!time) return 0;
      try {
        const [hours, minutes] = time.split(':').map(Number);
        // Ensure hours don't exceed 23
        const validHours = Math.min(hours, 23);
        return validHours * 60 + minutes;
      } catch (e) {
        console.warn('Invalid time format:', time);
        return 0;
      }
    },
    minutesToTime(minutes) {
      // Ensure we don't exceed 23:59
      minutes = Math.min(minutes, 23 * 60 + 59);
      const hours = Math.floor(minutes / 60);
      const mins = minutes % 60;
      return `${hours.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}`;
    },
    getTimeValue(day, type) {
      return this.timeIntervals[day]?.[type] || '00:00';
    }
  }
}
</script>

<template>
  <div class="weekly-schedule-container">
    <div class="schedule-layout">
      <!-- Days Column -->
      <div class="days-selection">
        <button v-for="option in weeklyOptions" 
             :key="option.value"
             class="btn btn-outline-primary"
             :class="{ 
                 'active': selectedDays.includes(option.value)
             }"
             :disabled="!edit"
             @click="toggleDay(option.value)">
          {{ option.label }}
        </button>
      </div>

      <!-- Time Settings Column -->
      <div class="time-settings">
        <div v-for="day in selectedDays" 
             :key="day" 
             class="time-interval-row">
          <div class="day-label">{{ weeklyOptions.find(opt => opt.value === day).label }}</div>
          <div class="time-controls">
            <div class="time-inputs">
              <div class="time-input-group">
                <span>Start:</span>
                <input 
                  type="time" 
                  :value="getTimeValue(day, 'start')"
                  @input="e => updateTimeInterval(day, 'start', e.target.value)"
                  :disabled="!edit"
                  max="23:59"
                  class="time-input">
              </div>
              <div class="time-input-group">
                <span>End:</span>
                <input 
                  type="time" 
                  :value="getTimeValue(day, 'end')"
                  @input="e => updateTimeInterval(day, 'end', e.target.value)"
                  :disabled="!edit"
                  max="23:59"
                  class="time-input">
              </div>
            </div>
            <div class="slider-wrapper">
              <input 
                type="range" 
                class="time-slider start-handle" 
                :min="0" 
                :max="1440" 
                :value="timeToMinutes(getTimeValue(day, 'start'))"
                @input="e => updateTimeFromSlider(day, 'start', e.target.value)"
                :disabled="!edit">
              <input 
                type="range" 
                class="time-slider end-handle" 
                :min="0" 
                :max="1440" 
                :value="timeToMinutes(getTimeValue(day, 'end'))"
                @input="e => updateTimeFromSlider(day, 'end', e.target.value)"
                :disabled="!edit">
              <div class="slider-track"></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.weekly-schedule-container {
  padding: 1rem;
  background: var(--bs-dark);
  border-radius: 0.5rem;
  width: 100%;
}

.schedule-layout {
  display: flex;
  gap: 2rem;
  width: 100%;
  min-width: 0;
}

.days-selection {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  min-width: 120px;
  flex-shrink: 0;
}

.days-selection .btn {
  text-align: center;
  transition: all 0.2s ease;
  width: 100%;
}

.day-option {
  display: none;
}

.time-settings {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.time-interval-row {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.5rem;
  background: #191c1f;
  border-radius: 0.5rem;
  width: 100%;
}

.day-label {
  min-width: 100px;
  font-weight: 500;
}

.time-controls {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.time-inputs {
  position: relative;
  display: flex;
  justify-content: left;
  gap: 1rem;
}

.time-input-group {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.time-input {
  display: flex;
  width: 100%;
  padding: 0.25rem;
  border: 1px solid #373b3e;
  border-radius: 0.25rem;
  font-size: 0.8rem;
  background: #212529;
  color: #fff;
}

.time-input:disabled {
  background-color: rgba(13, 110, 253, 0.09);
  color: #0d6efd;
  border-color: transparent;
}

.slider-wrapper {
  position: relative;
  height: 40px;
  padding: 10px 0;
}

.time-slider {
  position: absolute;
  top: 50%;
  transform: translateY(-50%);
  width: 100%;
  -webkit-appearance: none;
  pointer-events: none;
  background: transparent;
  z-index: 3;
}

.time-slider::-webkit-slider-thumb {
  -webkit-appearance: none;
  pointer-events: auto;
  width: 16px;
  height: 16px;
  border-radius: 50%;
  background: #0d6efd;
  cursor: pointer;
  border: none;
}

.time-slider:disabled::-webkit-slider-thumb {
  background: rgba(13, 110, 253, 0.5);
  cursor: not-allowed;
}

.time-slider::-webkit-slider-runnable-track {
  -webkit-appearance: none;
  background: transparent;
}

.slider-track {
  position: absolute;
  top: 50%;
  transform: translateY(-50%);
  height: 4px;
  width: 100%;
  background: #373b3e;
  border-radius: 2px;
}
</style>