/**
 * A searchable single-select (combobox): type to filter a fixed option list,
 * click to pick. Shows the selected option's label when closed. Used by the
 * Flows search for the interface + protocol filters.
 */
import { useEffect, useId, useRef, useState } from "react";
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
  id?: string;
  "aria-label"?: string;
  "aria-labelledby"?: string;
}

export function SearchableSelect({
  options,
  value,
  onChange,
  placeholder,
  disabled,
  id,
  "aria-label": ariaLabel,
  "aria-labelledby": ariaLabelledBy,
}: SearchableSelectProps) {
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const blurRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const generatedId = useId();
  const inputId = id ?? `searchable-select-${generatedId}`;
  const listboxId = `${inputId}-listbox`;
  const [activeIndex, setActiveIndex] = useState(-1);

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

  const visible = filtered.slice(0, 100);
  const activeOption = activeIndex >= 0 ? visible[activeIndex] : undefined;

  useEffect(() => setActiveIndex(-1), [query, options]);

  return (
    <div className="relative">
      <Input
        id={inputId}
        role="combobox"
        aria-label={ariaLabel ?? (ariaLabelledBy ? undefined : placeholder ?? "Search options")}
        aria-labelledby={ariaLabelledBy}
        aria-autocomplete="list"
        aria-expanded={open && visible.length > 0}
        aria-controls={listboxId}
        aria-activedescendant={activeOption ? `${inputId}-option-${activeIndex}` : undefined}
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
        onKeyDown={(event) => {
          if (event.key === "ArrowDown" || event.key === "ArrowUp") {
            event.preventDefault();
            setOpen(true);
            const direction = event.key === "ArrowDown" ? 1 : -1;
            setActiveIndex((current) => {
              if (visible.length === 0) return -1;
              if (current < 0) return direction > 0 ? 0 : visible.length - 1;
              return (current + direction + visible.length) % visible.length;
            });
          } else if (event.key === "Enter" && activeOption) {
            event.preventDefault();
            pick(activeOption);
          } else if (event.key === "Escape") {
            setOpen(false);
            setActiveIndex(-1);
          } else if (event.key === "Tab") {
            setOpen(false);
          }
        }}
      />
      {open && visible.length > 0 && (
        <ul id={listboxId} role="listbox" className="absolute z-50 mt-1 max-h-60 w-full overflow-auto rounded-md border bg-popover p-1 text-sm shadow-md">
          {visible.map((o, index) => (
            <li
              id={`${inputId}-option-${index}`}
              role="option"
              aria-selected={o.value === value}
              key={o.value}
              className={`cursor-default rounded px-2 py-1 ${
                  index === activeIndex || o.value === value ? "bg-accent text-accent-foreground" : ""
                }`}
              onMouseEnter={() => setActiveIndex(index)}
              onMouseDown={(event) => { event.preventDefault(); pick(o); }}
            >
              {o.label}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
