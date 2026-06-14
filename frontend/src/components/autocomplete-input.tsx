/**
 * Debounced autocomplete text input. Fetches suggestions lazily (250 ms after
 * the user stops typing) and guards against out-of-order responses with a
 * sequence counter, so the dropdown always reflects the latest query. Used by
 * the Flows search (source / destination / port).
 */
import { useEffect, useRef, useState } from "react";
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
}

export function AutocompleteInput({
  value,
  onChange,
  fetchSuggestions,
  placeholder,
  onEnter,
  inputMode = "text",
}: AutocompleteInputProps) {
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [open, setOpen] = useState(false);
  const seqRef = useRef(0);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const blurRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      const seq = ++seqRef.current;
      fetchSuggestions(value)
        .then((vals) => {
          if (seq === seqRef.current) setSuggestions(vals);
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
          if (e.key === "Enter") {
            setOpen(false);
            onEnter?.();
          } else if (e.key === "Escape") {
            setOpen(false);
          }
        }}
      />
      {showList && (
        <ul className="absolute z-50 mt-1 max-h-60 w-full overflow-auto rounded-md border bg-popover p-1 text-sm shadow-md">
          {suggestions.map((s) => (
            <li key={s}>
              <button
                type="button"
                className="block w-full rounded px-2 py-1 text-left font-mono hover:bg-accent hover:text-accent-foreground"
                // onMouseDown (not onClick) so it fires before the input blur.
                onMouseDown={(e) => {
                  e.preventDefault();
                  pick(s);
                }}
              >
                {s}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
