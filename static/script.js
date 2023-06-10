// Function to fetch new messages from the server
        function fetchMessages() {
            fetch('/get_messages')
                .then(response => response.json())
                .then(messages => {
                    // Process the retrieved messages and update the UI
                    updateMessageList(messages);
                });
        }

        // Function to update the message list in the UI
        function updateMessageList(messages) {
            const messageContainer = document.querySelector('.messages');
            messageContainer.innerHTML = '';
			
            // Iterate through the messages and add them to the list
            messages.forEach(message => {
				console.log(message)
				
				const sender = message.sender;
				const content = message.message;
				const timestamp = message.timestamp;
				const date = new Date(timestamp * 1000);
				const readableTime = date.toLocaleString();
			
				// Create message elements
				const messageDiv = document.createElement('div');
				messageDiv.classList.add('message');

				const senderDiv = document.createElement('div');
				senderDiv.classList.add('sender');
				senderDiv.innerHTML = `<p>${readableTime}</p><p>${sender}:</p>`;

				const contentDiv = document.createElement('div');
				contentDiv.classList.add('content');
				contentDiv.innerHTML = `<p>${content}</p>`;

				// Append sender and content to message div
				messageDiv.appendChild(senderDiv);
				messageDiv.appendChild(contentDiv);

				// Append message div to the message container
				messageContainer.appendChild(messageDiv);
				
				const chatBox = document.querySelector('.chat-box');
				chatBox.scrollTop = chatBox.scrollHeight;
            });
        }

        // Fetch new messages every 1 second
        setInterval(fetchMessages, 1000);

        // Function to send a new message
        function sendMessage(event) {
            event.preventDefault();

            const recipient = document.getElementById('recipient').value;
            const message = document.getElementById('message').value;

            // Send the message to the server using fetch
            fetch('/send_message', {
                method: 'POST',
                body: JSON.stringify({ recipient: recipient, message: message }),
                headers: {
                    'Content-Type': 'application/json'
                }
            })
            .then(response => {
                // Clear the input fields after sending the message
                document.getElementById('recipient').value = '';
                document.getElementById('message').value = '';
            });
        }