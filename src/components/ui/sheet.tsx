"use client";

import * as React from "react";
import { cn } from "@/lib/utils";

let bodyScrollLocks = 0;
let previousBodyOverflow = "";
let previousBodyPaddingRight = "";

function lockBodyScroll() {
  const body = document.body;

  if (bodyScrollLocks === 0) {
    previousBodyOverflow = body.style.overflow;
    previousBodyPaddingRight = body.style.paddingRight;
    const scrollbarWidth = Math.max(0, window.innerWidth - document.documentElement.clientWidth);
    const computedPadding = Number.parseFloat(window.getComputedStyle(body).paddingRight) || 0;

    body.style.overflow = "hidden";
    if (scrollbarWidth > 0) body.style.paddingRight = `${computedPadding + scrollbarWidth}px`;
  }

  bodyScrollLocks += 1;
  let released = false;

  return () => {
    if (released) return;
    released = true;
    bodyScrollLocks = Math.max(0, bodyScrollLocks - 1);
    if (bodyScrollLocks === 0) {
      body.style.overflow = previousBodyOverflow;
      body.style.paddingRight = previousBodyPaddingRight;
    }
  };
}

type SheetProps = {
  id: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  labelledBy: string;
  describedBy?: string;
  side?: "left" | "right";
  initialFocusRef?: React.RefObject<HTMLElement | null>;
  panelClassName?: string;
  dataUi?: string;
  children: React.ReactNode;
};

/**
 * A small, dependency-free modal sheet built on the native dialog top layer.
 * showModal() supplies focus containment and background inertness; this wrapper
 * adds controlled state, Escape/backdrop closing, scroll locking, and focus return.
 */
export function Sheet({
  id,
  open,
  onOpenChange,
  labelledBy,
  describedBy,
  side = "right",
  initialFocusRef,
  panelClassName,
  dataUi,
  children,
}: SheetProps) {
  const dialogRef = React.useRef<HTMLDialogElement>(null);
  const restoreFocusRef = React.useRef<HTMLElement | null>(null);

  React.useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog || !open) {
      if (dialog?.open) dialog.close();
      return;
    }

    restoreFocusRef.current = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
    const unlockBodyScroll = lockBodyScroll();
    if (!dialog.open) dialog.showModal();
    initialFocusRef?.current?.focus();

    return () => {
      if (dialog.open) dialog.close();
      unlockBodyScroll();
      const focusTarget = restoreFocusRef.current;
      if (focusTarget?.isConnected) focusTarget.focus();
    };
  }, [initialFocusRef, open]);

  return (
    <dialog
      ref={dialogRef}
      id={id}
      aria-labelledby={labelledBy}
      aria-describedby={describedBy}
      aria-modal="true"
      data-ui={dataUi}
      className="fixed inset-0 m-0 h-dvh max-h-none w-screen max-w-none border-0 bg-black/65 p-0 text-foreground"
      onCancel={(event) => {
        event.preventDefault();
        onOpenChange(false);
      }}
      onClick={(event) => {
        if (event.target === event.currentTarget) onOpenChange(false);
      }}
    >
      <div
        className={cn(
          "fixed inset-y-0 flex h-dvh w-full flex-col bg-card ring-1 ring-border",
          side === "left" ? "left-0" : "right-0",
          panelClassName,
        )}
      >
        {children}
      </div>
    </dialog>
  );
}
