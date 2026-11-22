// A "Print" button on a printable page (`data-print`): opens the browser's
// print dialog, where the page can also be saved as PDF.
document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-print]");
  if (button) {
    window.print();
  }
});
