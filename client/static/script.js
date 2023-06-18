let currentTab = null;
let groupTab = false;

function sendMessage() {
    var messageInput = document.getElementById("messageInput");
    var message = messageInput.value.trim();

    if (message === "") {
        alert("Please enter a message.");
        return;
    }

	
	if (groupTab == true) {
        var requestData = {
			members: currentTab.split(','),
			message: message
		};
		
		fetch("/send_group", {
	  method: "POST",
	  headers: {
		"Content-Type": "application/json"
	  },
	  body: JSON.stringify(requestData)
	})
	  .then(function(response) {
		if (response.ok) {
		  console.log(`Message sent successfully: ${JSON.stringify(requestData)}`);
		} else {
		  console.log("Failed to send message.");
		}
	  })
	  .catch(function(error) {
		console.log("Error occurred while sending the request:", error);
	  });
	
    messageInput.value = "";		
		
    }
    else {
        
	var requestData = {
	  recipient_username: currentTab,
	  message: message
	};

	fetch("/send", {
	  method: "POST",
	  headers: {
		"Content-Type": "application/json"
	  },
	  body: JSON.stringify(requestData)
	})
	  .then(function(response) {
		if (response.ok) {
		  console.log(`Message sent successfully: ${JSON.stringify(requestData)}`);
		} else {
		  console.log("Failed to send message.");
		}
	  })
	  .catch(function(error) {
		console.log("Error occurred while sending the request:", error);
	  });
	
    messageInput.value = "";
	}
}

function fetchMessages() {
  fetch('/message')
    .then(response => response.json())
    .then(messages => {
      updateTabList(messages);
    });
}

function updateTabList(messageData) {
  const tabsContainer = document.getElementById("chatsTab");
  tabsContainer.innerHTML = '';
	
  chatData = messageData['messages']
  groupData = messageData['group']
	
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
	  groupTab = false;
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
  
  for (const group in groupData) {
	  
	const groupName = group
	const messages = groupData[group]
	  
	const lastMessage = messages[messages.length - 1];
	const timestamp = lastMessage[3];
    const msg = lastMessage[2];
    const sender = lastMessage[0];
    const readableDate = new Date(timestamp * 1000).toLocaleString();
  
	const chatItem = document.createElement("a");
    chatItem.classList = "text-decoration-none py-2 px-3 mx-3 my-1 chatMessage";
    chatItem.href = "#";
    chatItem.onclick = function() {
      updateMessageList(groupName, groupData);
      currentTab = groupName;
	  groupTab = true;
    };

    const contentWrapper = document.createElement("div");
    contentWrapper.classList = "d-flex w-100 align-items-center justify-content-between";

    const title = document.createElement("strong");
    title.classList = "mb-1";
    title.innerHTML = groupName;

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
    if (groupTab == true) {
        updateMessageList(currentTab, groupData);
    }
    else {
        updateMessageList(currentTab, chatData);
    }
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
document.getElementById("sendButton").addEventListener("click", sendMessage);