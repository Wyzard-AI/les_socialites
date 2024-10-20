document.addEventListener('DOMContentLoaded', () => {
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
                        // Display the entire conversation based on isAdmin status
                        displayConversation(data.conversation);
                    }
                })
                .catch(error => console.error('Error fetching conversation:', error));
        }
    });

    function displayConversation(conversation) {
        const chatMessagesContainer = document.querySelector('.chat-messages');
        chatMessagesContainer.innerHTML = ''; // Clear previous messages

        conversation.forEach(message => {
            // If the user is an admin, show the entire conversation, otherwise filter for assistant messages only
            if (isAdmin || message.role === 'assistant') {
                const messageDiv = document.createElement('div');
                messageDiv.classList.add(message.role === 'user' ? 'message-user' : 'message');

                const senderDiv = document.createElement('div');
                senderDiv.classList.add(message.role === 'user' ? 'user-sender' : 'bot-sender');
                senderDiv.textContent = message.role === 'user' ? 'User:' : 'Wyzard AI:';

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
    }

    // Add event listener to the logout link
    const logoutLink = document.getElementById('logout-link');
    if (logoutLink) {
        logoutLink.addEventListener('click', function(event) {
            event.preventDefault(); // Prevent default anchor behavior
            window.location.href = '/logout'; // Redirect to the logout route
        });
    }
});
