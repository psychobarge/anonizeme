import { getVersion } from "@tauri-apps/api/app";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { LogicalSize } from "@tauri-apps/api/dpi";
import { getCurrentWindow } from "@tauri-apps/api/window";

const tabs = document.querySelectorAll(".tab") as NodeListOf<HTMLButtonElement>;
const dropZone = document.querySelector("#drop-zone") as HTMLElement;
const fileInput = document.querySelector("#file-input") as HTMLInputElement;
const fileNameEl = document.querySelector("#file-name") as HTMLElement;
const textInputSection = document.querySelector(
  "#text-input-section",
) as HTMLElement;
const textInput = document.querySelector("#text-input") as HTMLTextAreaElement;
const anonymizeBtn = document.querySelector("#anonymize-btn") as HTMLButtonElement;
const resultSection = document.querySelector("#result-section") as HTMLElement;
const previewEl = document.querySelector("#preview") as HTMLElement;
const copyBtn = document.querySelector("#copy-btn") as HTMLButtonElement;
const copyFeedback = document.querySelector("#copy-feedback") as HTMLElement;
const appVersionEl = document.querySelector("#app-version") as HTMLElement;

const WINDOW_WIDTH = 720;
const COMPACT_HEIGHT = 470;
const EXPANDED_HEIGHT = 760;

let fileContent = "";
let fileType: string | null = null;
let anonymizedResult = "";
let activeTab: "file" | "text" = "file";

async function resizeWindow(expanded: boolean): Promise<void> {
  const height = expanded ? EXPANDED_HEIGHT : COMPACT_HEIGHT;
  await getCurrentWindow().setSize(new LogicalSize(WINDOW_WIDTH, height));
}

function detectFileType(name: string): string | null {
  const lower = name.toLowerCase();
  if (lower.endsWith(".env")) return "env";
  if (lower.endsWith(".txt")) return "txt";
  return null;
}

function resetContentState(): void {
  fileContent = "";
  fileType = null;
  anonymizedResult = "";
  anonymizeBtn.disabled = true;
  resultSection.classList.add("hidden");
  void resizeWindow(false);
}

function setContentLoaded(content: string, type: string | null): void {
  fileContent = content;
  fileType = type;
  anonymizeBtn.disabled = !content.trim();
  resultSection.classList.add("hidden");
  anonymizedResult = "";
  void resizeWindow(false);
}

function setFileLoadedByName(name: string, content: string): void {
  setContentLoaded(content, detectFileType(name));
  fileNameEl.textContent = name;
  fileNameEl.classList.remove("hidden");
  dropZone.classList.add("has-file");
}

function setFileLoaded(file: File, content: string): void {
  setFileLoadedByName(file.name, content);
}

async function loadFileFromPath(filePath: string): Promise<void> {
  const { name, content } = await invoke<{ name: string; content: string }>(
    "read_text_file",
    { path: filePath },
  );
  setFileLoadedByName(name, content);
}

function setTextContent(content: string): void {
  setContentLoaded(content, null);
}

function switchTab(mode: "file" | "text"): void {
  activeTab = mode;
  tabs.forEach((tab) => {
    const isActive = tab.dataset.tab === mode;
    tab.classList.toggle("active", isActive);
    tab.setAttribute("aria-selected", String(isActive));
  });
  dropZone.classList.toggle("hidden", mode === "text");
  textInputSection.classList.toggle("hidden", mode === "file");
  resetContentState();

  if (mode === "file") {
    fileInput.value = "";
    fileNameEl.textContent = "";
    fileNameEl.classList.add("hidden");
    dropZone.classList.remove("has-file");
  } else {
    textInput.value = "";
  }
}

async function readFile(file: File): Promise<void> {
  const content = await file.text();
  setFileLoaded(file, content);
}

function handleFiles(files: FileList | null): void {
  if (!files || files.length === 0) return;
  void readFile(files[0]);
}

function highlightPlaceholders(text: string): string {
  const escaped = text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

  return escaped.replace(
    /&lt;([A-Z][A-Z0-9_]*_\d+)&gt;|&lt;REDACTED&gt;/g,
    '<span class="placeholder">$&</span>',
  );
}

async function anonymize(): Promise<void> {
  if (!fileContent.trim()) return;

  anonymizeBtn.disabled = true;
  anonymizeBtn.textContent = "Anonymisation…";

  try {
    anonymizedResult = await invoke<string>("anonymize_text", {
      content: fileContent,
      fileType,
    });
    previewEl.innerHTML = highlightPlaceholders(anonymizedResult);
    resultSection.classList.remove("hidden");
    copyFeedback.classList.add("hidden");
    await resizeWindow(true);
  } catch (error) {
    previewEl.textContent =
      error instanceof Error ? error.message : String(error);
    resultSection.classList.remove("hidden");
    await resizeWindow(true);
  } finally {
    anonymizeBtn.disabled = false;
    anonymizeBtn.textContent = "Anon-ize-me";
  }
}

async function copyResult(): Promise<void> {
  if (!anonymizedResult) return;
  await navigator.clipboard.writeText(anonymizedResult);
  copyFeedback.classList.remove("hidden");
  copyBtn.textContent = "Copié !";
  window.setTimeout(() => {
    copyFeedback.classList.add("hidden");
    copyBtn.textContent = "Copier";
  }, 2000);
}

tabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    const mode = tab.dataset.tab as "file" | "text";
    if (mode && mode !== activeTab) {
      switchTab(mode);
    }
  });
});

textInput.addEventListener("input", () => {
  setTextContent(textInput.value);
});

dropZone.addEventListener("click", () => fileInput.click());

dropZone.addEventListener("keydown", (event) => {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    fileInput.click();
  }
});

fileInput.addEventListener("change", () => handleFiles(fileInput.files));

function setupHtmlFileDrop(): void {
  dropZone.addEventListener("dragover", (event) => {
    event.preventDefault();
    dropZone.classList.add("drag-over");
  });

  dropZone.addEventListener("dragleave", () => {
    dropZone.classList.remove("drag-over");
  });

  dropZone.addEventListener("drop", (event) => {
    event.preventDefault();
    dropZone.classList.remove("drag-over");
    handleFiles(event.dataTransfer?.files ?? null);
  });
}

async function setupNativeFileDrop(): Promise<void> {
  await getCurrentWindow().onDragDropEvent((event) => {
    if (activeTab !== "file") return;

    const { payload } = event;
    if (payload.type === "enter" || payload.type === "over") {
      dropZone.classList.add("drag-over");
      return;
    }

    dropZone.classList.remove("drag-over");

    if (payload.type === "drop" && payload.paths.length > 0) {
      void loadFileFromPath(payload.paths[0]).catch((error) => {
        console.error("Failed to load dropped file:", error);
      });
    }
  });
}

if (isTauri()) {
  void setupNativeFileDrop();
} else {
  setupHtmlFileDrop();
}

anonymizeBtn.addEventListener("click", () => void anonymize());
copyBtn.addEventListener("click", () => void copyResult());

void getVersion().then((version) => {
  appVersionEl.textContent = `v${version}`;
});
