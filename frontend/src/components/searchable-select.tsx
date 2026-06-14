/**
 * A searchable single-select (combobox): type to filter a fixed option list,
 * click to pick. Shows the selected option's label when closed. Used by the
 * Flows search for the interface + protocol filters.
 */
import { useEffect, useRef, useState } from "react";
import { Input } from "@/components/ui/input";

export interface SelectOption {
  value: string;
  label: string;
}

interface SearchableSelectProps {
  options: SelectOption[];
  /** Selected option value ("" = none). */
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  disabled?: boolean;
}

export function SearchableSelect({
  options,
  value,
  onChange,
  placeholder,
  disabled,
}: SearchableSelectProps) {
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const blurRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(
    () => () => {
      if (blurRef.current) clearTimeout(blurRef.current);
    },
    [],
  );

  const selected = options.find((o) => o.value === value);
  // While open, show what the user is typing; while closed, the selected label.
  const display = open ? query : selected?.label ?? "";
  const q = query.trim().toLowerCase();
  const filtered = open
    ? options.filter(
        (o) => o.label.toLowerCase().includes(q) || o.value.toLowerCase().includes(q),
      )
    : [];

  const pick = (o: SelectOption) => {
    onChange(o.value);
    setQuery("");
    setOpen(false);
  };

  return (
    <div className="relative">
      <Input
        value={display}
        placeholder={placeholder}
        disabled={disabled}
        autoComplete="off"
        onChange={(e) => {
          setQuery(e.target.value);
          setOpen(true);
        }}
        onFocus={() => {
          setQuery("");
          setOpen(true);
        }}
        onBlur={() => {
          blurRef.current = setTimeout(() => setOpen(false), 150);
        }}
      />
      {open && filtered.length > 0 && (
        <ul className="absolute z-50 mt-1 max-h-60 w-full overflow-auto rounded-md border bg-popover p-1 text-sm shadow-md">
          {filtered.slice(0, 100).map((o) => (
            <li key={o.value}>
              <button
                type="button"
                className={`block w-full rounded px-2 py-1 text-left hover:bg-accent hover:text-accent-foreground ${
                  o.value === value ? "bg-accent/50" : ""
                }`}
                // onMouseDown (not onClick) so it fires before the input blur.
                onMouseDown={(e) => {
                  e.preventDefault();
                  pick(o);
                }}
              >
                {o.label}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
