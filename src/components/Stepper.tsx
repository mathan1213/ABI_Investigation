import React from 'react';
import { Check } from 'lucide-react';

export interface StepItem {
  id: number;
  title: string;
  description?: string;
}

interface StepperProps {
  steps: StepItem[];
  currentStep: number;
  className?: string;
}

export const Stepper: React.FC<StepperProps> = ({ steps, currentStep, className = '' }) => {
  return (
    <div className={`w-full ${className}`}>
      {/* Desktop Stepper */}
      <div className="hidden sm:flex items-center justify-between relative">
        {/* Continuous background bar */}
        <div className="absolute top-1/2 left-0 right-0 h-0.5 bg-slate-800 -translate-y-1/2 z-0" />
        {/* Dynamic active progress bar */}
        <div
          className="absolute top-1/2 left-0 h-0.5 bg-cyan-400 -translate-y-1/2 z-0 transition-all duration-500"
          style={{
            width: `${((Math.min(currentStep, steps.length) - 1) / (steps.length - 1)) * 100}%`,
          }}
        />

        {steps.map((step) => {
          const isCompleted = step.id < currentStep;
          const isCurrent = step.id === currentStep;

          return (
            <div key={step.id} className="relative z-10 flex flex-col items-center">
              <div
                className={`w-10 h-10 rounded-full flex items-center justify-center font-bold text-sm transition-all duration-300 ${
                  isCompleted
                    ? 'bg-cyan-500 text-slate-950 ring-4 ring-cyan-500/20 shadow-glow'
                    : isCurrent
                    ? 'bg-slate-900 border-2 border-cyan-400 text-cyan-300 ring-4 ring-cyan-400/20 shadow-glow'
                    : 'bg-slate-900 border border-slate-700 text-slate-400'
                }`}
              >
                {isCompleted ? <Check size={18} strokeWidth={2.5} /> : step.id}
              </div>
              <div className="text-center mt-2.5">
                <span
                  className={`text-xs font-semibold block transition-colors ${
                    isCurrent ? 'text-cyan-300' : isCompleted ? 'text-slate-200' : 'text-slate-400'
                  }`}
                >
                  {step.title}
                </span>
                {step.description && (
                  <span className="text-[11px] text-slate-400 hidden md:block">
                    {step.description}
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Mobile Stepper */}
      <div className="sm:hidden flex items-center justify-between px-2">
        <div className="flex items-center gap-2">
          <span className="flex h-7 w-7 items-center justify-center rounded-full bg-cyan-500 text-xs font-bold text-slate-950">
            {currentStep}
          </span>
          <div>
            <span className="text-xs text-slate-400">Step {currentStep} of {steps.length}</span>
            <div className="text-sm font-semibold text-white">
              {steps.find((s) => s.id === currentStep)?.title}
            </div>
          </div>
        </div>
        <div className="flex gap-1.5">
          {steps.map((step) => (
            <div
              key={step.id}
              className={`h-1.5 w-6 rounded-full transition-all duration-300 ${
                step.id <= currentStep ? 'bg-cyan-400' : 'bg-slate-800'
              }`}
            />
          ))}
        </div>
      </div>
    </div>
  );
};
