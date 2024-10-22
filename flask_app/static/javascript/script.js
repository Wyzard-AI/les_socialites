document.addEventListener('DOMContentLoaded', () => {
    let lastMessageIndex = 0; // To keep track of the last message index displayed

    // Fetch the prompts dynamically and populate the assistant buttons
    fetch('/get_prompts')
        .then(response => response.json())
        .then(data => {
            const assistantButtonsContainer = document.querySelector('.assistant-buttons');

            // Clear existing static buttons
            assistantButtonsContainer.innerHTML = '';

            // Iterate through each category in the fetched data
            for (const category in data) {
                const buttonDiv = document.createElement('div');
                buttonDiv.classList.add('button');
                buttonDiv.setAttribute('data-category', category); // Set a data attribute for the category
                buttonDiv.textContent = category;

                const submenuDiv = document.createElement('div');
                submenuDiv.classList.add('submenu');

                // Iterate through each subcategory in the category
                for (const subcategory in data[category]) {
                    const submenuItemDiv = document.createElement('div');
                    submenuItemDiv.classList.add('submenu-item');
                    submenuItemDiv.setAttribute('data-subcategory', subcategory); // Set a data attribute for the subcategory

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
                        buttonLink.classList.add('button-name'); // Adding a class to target these buttons
                        buttonLink.setAttribute('data-button-name', buttonName); // Set a data attribute for the button name
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

    // Event delegation to handle button clicks dynamically
    document.body.addEventListener('click', (event) => {
        if (event.target.classList.contains('button-name')) {
            event.preventDefault(); // Prevent the default anchor behavior

            const buttonName = event.target.getAttribute('data-button-name');
            const subcategory = event.target.closest('.submenu-item').getAttribute('data-subcategory');
            const category = event.target.closest('.button').getAttribute('data-category');

            // Fetch the prompt and entire conversation for the selected category, subcategory, and button_name
            fetch(`/get_prompt_for_openai_assistant_response?category=${encodeURIComponent(category)}&subcategory=${encodeURIComponent(subcategory)}&button_name=${encodeURIComponent(buttonName)}`)
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Network response was not ok');
                    }
                    return response.json();
                })
                .then(data => {
                    if (data.error) {
                        console.error('Error fetching conversation:', data.error);
                    } else {
                        // Display only new messages
                        displayNewMessages(data.conversation);
                    }
                })
                .catch(error => console.error('Error fetching conversation:', error));
        }
    });

    function displayNewMessages(conversation) {
        const chatMessagesContainer = document.querySelector('.chat-messages');
        const newMessages = conversation.slice(lastMessageIndex);

        newMessages.forEach(message => {
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
                const messageDiv = document.createElement('div');
                messageDiv.classList.add('message');

                const senderDiv = document.createElement('div');
                // Set a custom class for system messages
                senderDiv.classList.add(
                    message.role === 'user' ? 'user-sender' :
                    message.role === 'assistant' ? 'bot-sender' :
                    'system-sender' // Custom class for system messages
                );

                // Update the sender label based on the role
                if (message.role === 'user') {
                    senderDiv.textContent = 'User:';
                } else if (message.role === 'assistant') {
                    senderDiv.textContent = 'Wyzard AI:';
                } else if (message.role === 'system') {
                    senderDiv.textContent = 'System Instructions:'; // Label for system messages
                }

                const textDiv = document.createElement('div');
                textDiv.classList.add('text');

                message.content_parts.forEach(part => {
                    if (part.type === 'text') {
                        textDiv.innerHTML += `<p>${part.content}</p>`;
                    } else if (part.type === 'code') {
                        textDiv.innerHTML += `<pre><code>${part.content}</code></pre>`;
                    }
                });

                messageDiv.appendChild(senderDiv);
                messageDiv.appendChild(textDiv);
                chatMessagesContainer.appendChild(messageDiv);
            }
        });

        // Update the lastMessageIndex to the latest message
        lastMessageIndex = conversation.length;
    }

    // Add event listener to the logout link
    const logoutLink = document.getElementById('logout-link');
    if (logoutLink) {
        logoutLink.addEventListener('click', function(event) {
            event.preventDefault(); // Prevent default anchor behavior
            window.location.href = '/logout'; // Redirect to the logout route
        });
    }

    // Handle the form submission for user messages and file uploads
    const chatForm = document.getElementById('chat-form');
    const chatInput = document.getElementById('chat-input');
    const fileInput = document.getElementById('file-upload');

    chatForm.addEventListener('submit', (event) => {
        event.preventDefault(); // Prevent the default form submission behavior

        const prompt = chatInput.value.trim();
        const file = fileInput.files[0];

        // Check if the prompt is not empty
        if (!prompt) {
            alert("Please enter a prompt.");
            return;
        }

        // Create a FormData object to hold the form data
        const formData = new FormData();
        formData.append('prompt', prompt);

        // Append the file if one is selected
        if (file) {
            formData.append('file', file);
        }

        // Send the form data to the Flask backend using fetch
        fetch('/send_typed_prompt_for_openai_assistant_response', {
            method: 'POST',
            body: formData
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            if (data.error) {
                console.error('Error sending message:', data.error);
            } else {
                // Update the conversation display with the new message
                displayNewMessages(data.conversation);
                chatInput.value = ''; // Clear the input field
                fileInput.value = ''; // Clear the file input
            }
        })
        .catch(error => console.error('Error sending message:', error));
    });
});
