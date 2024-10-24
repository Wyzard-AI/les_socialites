document.addEventListener('DOMContentLoaded', () => {
    let lastMessageIndex = 0; // To keep track of the last message index displayed

    // Fetch the prompts dynamically and populate the assistant buttons
    fetchPrompts();

    function fetchPrompts() {
        fetch('/get_prompts')
            .then(response => response.json())
            .then(data => {
                const assistantButtonsContainer = document.querySelector('.assistant-buttons');
                assistantButtonsContainer.innerHTML = ''; // Clear existing static buttons

                // Iterate through each category in the fetched data
                for (const category in data) {
                    const buttonDiv = document.createElement('div');
                    buttonDiv.classList.add('button');
                    buttonDiv.setAttribute('data-category', category);
                    buttonDiv.textContent = category;

                    const submenuDiv = document.createElement('div');
                    submenuDiv.classList.add('submenu');

                    // Iterate through each subcategory in the category
                    for (const subcategory in data[category]) {
                        const submenuItemDiv = document.createElement('div');
                        submenuItemDiv.classList.add('submenu-item');
                        submenuItemDiv.setAttribute('data-subcategory', subcategory);

                        const subcategoryLink = document.createElement('a');
                        subcategoryLink.href = '#';
                        subcategoryLink.textContent = subcategory;

                        const subSubmenuDiv = document.createElement('div');
                        subSubmenuDiv.classList.add('sub-submenu');

                        // Iterate through each button name in the subcategory
                        data[category][subcategory].forEach(buttonName => {
                            const buttonLink = document.createElement('a');
                            buttonLink.href = '#';
                            buttonLink.textContent = buttonName;
                            buttonLink.classList.add('button-name');
                            buttonLink.setAttribute('data-button-name', buttonName);
                            subSubmenuDiv.appendChild(buttonLink);
                        });

                        submenuItemDiv.appendChild(subcategoryLink);
                        submenuItemDiv.appendChild(subSubmenuDiv);
                        submenuDiv.appendChild(submenuItemDiv);
                    }

                    buttonDiv.appendChild(submenuDiv);
                    assistantButtonsContainer.appendChild(buttonDiv);
                }
            })
            .catch(error => console.error('Error fetching prompts:', error));
    }

    // Event delegation to handle button clicks dynamically
    document.body.addEventListener('click', (event) => {
        if (event.target.classList.contains('button-name')) {
            event.preventDefault(); // Prevent the default anchor behavior

            const buttonName = event.target.getAttribute('data-button-name');
            const subcategory = event.target.closest('.submenu-item').getAttribute('data-subcategory');
            const category = event.target.closest('.button').getAttribute('data-category');

            console.log('Prompt selected:', { category, subcategory, buttonName });

            // Show loading animation
            const loadingAnimation = document.getElementById('loading-animation');
            loadingAnimation.style.display = 'flex';

            // Reset the lastMessageIndex and clear the chat window
            lastMessageIndex = 0;
            clearChatWindow();

            // Delete the conversation on the backend and fetch the new prompt
            deleteConversationAndFetchPrompt(category, subcategory, buttonName)
                .then(conversation => {
                    console.log('Fetched conversation:', conversation);
                    displayNewMessages(conversation);
                })
                .catch(error => console.error('Error fetching conversation:', error))
                .finally(() => {
                    loadingAnimation.style.display = 'none';
                });
        }
    });

    function clearChatWindow() {
        const chatMessagesContainer = document.querySelector('.chat-messages');
        chatMessagesContainer.innerHTML = ''; // Clear existing messages
    }

    function deleteConversationAndFetchPrompt(category, subcategory, buttonName) {
        console.log('Deleting conversation for:', { category, subcategory, buttonName });
        return fetch('/delete_conversation', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ category, subcategory, buttonName })
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(() => {
            console.log('Conversation deleted. Fetching new prompt...');
            return fetch(`/get_prompt_for_openai_assistant_response?category=${encodeURIComponent(category)}&subcategory=${encodeURIComponent(subcategory)}&button_name=${encodeURIComponent(buttonName)}`)
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Network response was not ok');
                    }
                    return response.json();
                })
                .then(data => {
                    console.log('Received data:', data);

                    if (data.error) {
                        console.error('Error fetching conversation:', data.error);
                        return Promise.reject(data.error);
                    }

                    if (data.conversation) {
                        return data.conversation;
                    } else {
                        console.error('No conversation returned in response.');
                        return Promise.reject('No conversation found.');
                    }
                });
        });
    }

    function displayNewMessages(conversation) {
        const chatMessagesContainer = document.querySelector('.chat-messages');

        console.log("displayNewMessages called with conversation:", conversation);

        // Ensure the conversation is an array
        if (!Array.isArray(conversation)) {
            console.error("Invalid conversation format received:", conversation);
            return;
        }

        // Iterate through each message and display it
        conversation.forEach(message => {
            let displayMessage = false;

            // Admins see all messages
            if (isAdmin) {
                displayMessage = true;
            } else {
                // Non-admins only see user messages without the specific phrase and assistant messages
                if (message.role === 'assistant') {
                    displayMessage = true;
                } else if (message.role === 'user' && !message.content.includes("Please answer the following prompt:")) {
                    displayMessage = true;
                }
            }

            // If the message should be displayed, create the message elements
            if (displayMessage) {
                console.log("Displaying message:", message);

                const messageDiv = document.createElement('div');
                messageDiv.classList.add('message');

                const senderDiv = document.createElement('div');
                senderDiv.classList.add(
                    message.role === 'user' ? 'user-sender' :
                    message.role === 'assistant' ? 'bot-sender' :
                    'system-sender'
                );

                if (message.role === 'user') {
                    senderDiv.textContent = 'User:';
                } else if (message.role === 'assistant') {
                    senderDiv.textContent = 'Wyzard AI:';
                } else if (message.role === 'system') {
                    senderDiv.textContent = 'System Instructions:';
                }

                const textDiv = document.createElement('div');
                textDiv.classList.add('text');

                // Safely set the HTML content from content_parts
                if (Array.isArray(message.content_parts)) {
                    message.content_parts.forEach(part => {
                        const paragraph = document.createElement('div');
                        paragraph.innerHTML = part.content;
                        textDiv.appendChild(paragraph);
                    });
                } else {
                    console.error("Unexpected content_parts format:", message.content_parts);
                }

                messageDiv.appendChild(senderDiv);
                messageDiv.appendChild(textDiv);
                chatMessagesContainer.appendChild(messageDiv);
            }
        });

        // Update the lastMessageIndex to the latest message
        lastMessageIndex = conversation.length;

        // Scroll to the latest message
        chatMessagesContainer.scrollTop = chatMessagesContainer.scrollHeight;
    }
});
