/**
 * The little UI NEAR Auth draws inside the connector's sandbox panel. The Auth0 modal itself lives
 * in a popup, so this is only needed when the sandbox has to ask something the popup cannot.
 */

const styles = /* css */ `
  .near-auth {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
    max-width: 360px;
    padding: 24px;
  }

  .near-auth h1 {
    margin: 0;
    font-size: 20px;
    font-weight: 600;
  }

  .near-auth p {
    margin: 0 0 8px;
    font-size: 14px;
    color: rgb(170, 170, 170);
  }

  .near-auth-accounts {
    display: flex;
    flex-direction: column;
    gap: 8px;
    width: 100%;
    max-height: 260px;
    overflow-y: auto;
  }

  .near-auth-account {
    width: 100%;
    padding: 12px 16px;
    border: 1px solid rgb(64, 64, 64);
    border-radius: 12px;
    background-color: rgb(25, 25, 25);
    color: rgb(255, 255, 255);
    font-family: inherit;
    font-size: 14px;
    font-weight: 500;
    text-align: left;
    overflow-wrap: anywhere;
    cursor: pointer;
  }

  .near-auth-account:hover {
    border-color: rgb(0, 236, 151);
  }
`;

const root = (): HTMLElement => {
  const element = document.getElementById("root");
  if (!element) throw new Error("NEAR Auth sandbox is not ready");
  return element;
};

const show = (html: string) => {
  const element = root();
  element.style.display = "flex";
  element.innerHTML = `<style>${styles}</style>${html}`;
  window.selector.ui.showIframe();
};

export const hide = () => {
  root().innerHTML = "";
  window.selector.ui.hideIframe();
};

/** Lets the user choose when the derived key controls more than one account. */
export const pickAccount = (accountIds: string[]): Promise<string> => {
  show(/* html */ `
    <div class="near-auth">
      <h1>Choose an account</h1>
      <p>Your NEAR Auth key controls more than one account.</p>
      <div class="near-auth-accounts">
        ${accountIds.map((id, index) => `<button class="near-auth-account" data-index="${index}">${id}</button>`).join("")}
      </div>
    </div>
  `);

  return new Promise<string>((resolve) => {
    root()
      .querySelectorAll<HTMLButtonElement>(".near-auth-account")
      .forEach((button) => {
        button.addEventListener("click", () => {
          hide();
          resolve(accountIds[Number(button.dataset.index)]);
        });
      });
  });
};
