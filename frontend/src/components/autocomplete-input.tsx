/**
 * Debounced autocomplete text input. Fetches suggestions lazily (250 ms after
 * the user stops typing) and guards against out-of-order responses with a
 * sequence counter, so the dropdown always reflects the latest query. Used by
 * the Flows search (source / destination / port).
 */
import { useEffect, useId, useRef, useState } from "react";
import { Input } from "@/components/ui/input";

interface AutocompleteInputProps {
  value: string;
  onChange: (v: string) => void;
  /** Memoize in the parent (e.g. useCallback keyed on device) so it changes
   *  only when the suggestion scope changes. */
  fetchSuggestions: (q: string) => Promise<string[]>;
  placeholder?: string;
  onEnter?: () => void;
  inputMode?: "text" | "numeric";
  id?: string;
  "aria-label"?: string;
  "aria-labelledby"?: string;
}

export function AutocompleteInput({
  value,
  onChange,
  fetchSuggestions,
  placeholder,
  onEnter,
  inputMode = "text",
  id,
  "aria-label": ariaLabel,
  "aria-labelledby": ariaLabelledBy,
}: AutocompleteInputProps) {
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [open, setOpen] = useState(false);
  const seqRef = useRef(0);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const blurRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const generatedId = useId();
  const inputId = id ?? `autocomplete-${generatedId}`;
  const listboxId = `${inputId}-listbox`;
  const [activeIndex, setActiveIndex] = useState(-1);

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      const seq = ++seqRef.current;
      fetchSuggestions(value)
        .then((vals) => {
          if (seq === seqRef.current) {
            setSuggestions(vals);
            setActiveIndex(-1);
          }
        })
        .catch(() => {
          if (seq === seqRef.current) setSuggestions([]);
        });
    }, 250);
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [value, fetchSuggestions]);

  // Clean up the blur timer on unmount.
  useEffect(() => () => {
    if (blurRef.current) clearTimeout(blurRef.current);
  }, []);

  const pick = (v: string) => {
    onChange(v);
    setOpen(false);
  };

  const showList = open && suggestions.length > 0;

  return (
    <div className="relative">
      <Input
        id={inputId}
        role="combobox"
        aria-label={ariaLabel ?? (ariaLabelledBy ? undefined : placeholder ?? "Search suggestions")}
        aria-labelledby={ariaLabelledBy}
        aria-autocomplete="list"
        aria-expanded={showList}
        aria-controls={listboxId}
        aria-activedescendant={activeIndex >= 0 ? `${inputId}-option-${activeIndex}` : undefined}
        value={value}
        inputMode={inputMode}
        placeholder={placeholder}
        autoComplete="off"
        onChange={(e) => {
          onChange(e.target.value);
          setOpen(true);
        }}
        onFocus={() => setOpen(true)}
        // Delay close so a click on a suggestion registers first.
        onBlur={() => {
          blurRef.current = setTimeout(() => setOpen(false), 150);
        }}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown" || e.key === "ArrowUp") {
            e.preventDefault();
            setOpen(true);
            const direction = e.key === "ArrowDown" ? 1 : -1;
            setActiveIndex((current) => {
              if (suggestions.length === 0) return -1;
              if (current < 0) return direction > 0 ? 0 : suggestions.length - 1;
              return (current + direction + suggestions.length) % suggestions.length;
            });
          } else if (e.key === "Enter" && activeIndex >= 0) {
            e.preventDefault();
            pick(suggestions[activeIndex]);
          } else if (e.key === "Enter") {
            setOpen(false);
            onEnter?.();
          } else if (e.key === "Escape") {
            setOpen(false);
            setActiveIndex(-1);
          } else if (e.key === "Tab") {
            setOpen(false);
          }
        }}
      />
      {showList && (
        <ul id={listboxId} role="listbox" className="absolute z-50 mt-1 max-h-60 w-full overflow-auto rounded-md border bg-popover p-1 text-sm shadow-md">
          {suggestions.map((s, index) => (
            <li
              id={`${inputId}-option-${index}`}
              role="option"
              aria-selected={index === activeIndex}
              key={s}
              className={`cursor-default rounded px-2 py-1 font-mono ${index === activeIndex ? "bg-accent text-accent-foreground" : ""}`}
              onMouseEnter={() => setActiveIndex(index)}
              onMouseDown={(event) => { event.preventDefault(); pick(s); }}
            >
              {s}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
