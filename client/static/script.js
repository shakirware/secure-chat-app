let currentTab = null;

function fetchMessages() {
  fetch('/message')
    .then(response => response.json())
    .then(messages => {
      updateTabList(messages);
    });
}

function updateTabList(chatData) {
  const tabsContainer = document.getElementById("chatsTab");
  tabsContainer.innerHTML = '';

  for (const user in chatData) {
    const messages = chatData[user];
    const lastMessage = messages[messages.length - 1];
    const timestamp = lastMessage[3];
    const msg = lastMessage[2];
    const sender = lastMessage[0];
    const readableDate = new Date(timestamp * 1000).toLocaleString();

    const chatItem = document.createElement("a");
    chatItem.classList = "text-decoration-none py-2 px-3 mx-3 my-1 chatMessage";
    chatItem.href = "#";
    chatItem.onclick = function() {
      updateMessageList(user, chatData);
      currentTab = user;
    };

    const contentWrapper = document.createElement("div");
    contentWrapper.classList = "d-flex w-100 align-items-center justify-content-between";

    const title = document.createElement("strong");
    title.classList = "mb-1";
    title.innerHTML = user;

    const date = document.createElement("small");
    date.innerHTML = readableDate;

    contentWrapper.appendChild(title);
    contentWrapper.appendChild(date);

    const description = document.createElement("div");
    description.classList = "col-10 mb-1 small";
    description.innerHTML = msg;

    chatItem.appendChild(contentWrapper);
    chatItem.appendChild(description);

    tabsContainer.appendChild(chatItem);
  }

  if (currentTab != null) {
    updateMessageList(currentTab, chatData);
  }
}

function updateMessageList(user, chatData) {
  const messages = chatData[user];
  const chatContainer = document.getElementById("chatMessages");
  chatContainer.innerHTML = '';

  for (let i = 0; i < messages.length; i++) {
    const message = messages[i];
    const timestamp = message[3];
    const msg = message[2];
    const sender = message[0];
    const readableDate = new Date(timestamp * 1000).toLocaleString();

    const test = document.createElement("div");
    test.classList = "rounded rounded-lg shadow";
    test.style.background = "#446";
    test.style.margin = "10px 5px";

    const contentWrapper = document.createElement("div");
    contentWrapper.classList = "d-flex w-100 align-items-center justify-content-between";

    const title = document.createElement("b");
    title.innerHTML = sender;
    title.style.paddingLeft = "10px";
    title.style.color = "#ddd";

    const date = document.createElement("b");
    date.innerHTML = readableDate;
    date.style.paddingRight = "10px";
    date.style.marginLeft = "auto";
    date.style.color = "#ddd";

    const text = document.createElement("p");
    text.innerHTML = msg;
    text.style.margin = "8px 8px 15px 8px";
    text.style.padding = "5px";
    text.style.color = "#cdd";

    contentWrapper.appendChild(title);
    contentWrapper.appendChild(date);
    test.appendChild(contentWrapper);
    test.appendChild(text);
    chatContainer.appendChild(test);
    chatContainer.scrollTop = chatContainer.scrollHeight;
  }
}

setInterval(fetchMessages, 1000);