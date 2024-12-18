document.addEventListener('DOMContentLoaded', () => {
    let lastMessageIndex = 0;

    const categoryEmojis = {
        "Accounting": "📄",
        "Administrative Assistant": "💻",
        "Business Developer": "🤝",
        "Content Creation": "📸",
        "Customer Service": "📞",
        "Data Analyst": "📊",
        "Design": "🎨",
        "eCommerce": "🛒",
        "Event Planning": "🎉",
        "HR": "💼",
        "Humanizer": "🧠",
        "Influencer": "🤩",
        "Influencer Marketing": "🤳",
        "Legal Advisor": "⚖️",
        "Marketing": "📣",
        "Multi-Channel Campaign": "💌",
        "Plagiarism Checker": "✅",
        "PR": "📰",
        "Project Manager": "📋",
        "Sales": "💰",
        "SEO": "🔍",
        "Social Media": "❤️",
        "Spellcheck/Translation": "✍️",
        "Personal Assistant": "🤖",
        "Web": "🌐"
    };

    // Initialize everything when the DOM content is fully loaded
    fetchPrompts();
    initNewsletterForm();
    initChatFunctionality();
    initChatForm();
    initLogout();
    showLoadingAnimation();
    hideLoadingAnimation();

    // Utility functions for loading animation
    function showLoadingAnimation() {
        const loadingAnimation = document.getElementById('loading-animation');
        if (loadingAnimation) {
            loadingAnimation.style.display = 'flex'; // Ensure it's displayed
        }
    }

    function hideLoadingAnimation() {
        const loadingAnimation = document.getElementById('loading-animation');
        if (loadingAnimation) {
            loadingAnimation.style.display = 'none'; // Hide it
        }
    }

    // Function for initializing the newsletter form submission
    function initNewsletterForm() {
        const newsletterForm = document.getElementById('newsletter-form');
        if (newsletterForm) {
            newsletterForm.addEventListener('submit', function(event) {
                event.preventDefault();

                const formData = new FormData(newsletterForm);

                fetch('/submit-newsletter', {
                    method: 'POST',
                    body: formData,
                })
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Network response was not ok');
                    }
                    return response.json();
                })
                .then(data => {
                    const messageElement = document.getElementById('newsletter-message');
                    if (data.success) {
                        messageElement.textContent = data.message;
                        messageElement.style.color = 'green';
                    } else {
                        messageElement.textContent = data.message || 'Subscription failed. Please try again.';
                        messageElement.style.color = 'red';
                    }
                })
                .catch(error => {
                    console.error('Error submitting newsletter form:', error);
                    const messageElement = document.getElementById('newsletter-message');
                    messageElement.textContent = 'An error occurred. Please try again.';
                    messageElement.style.color = 'red';
                });
            });
        }
    }

    // Function for fetching and displaying prompts dynamically
    function fetchPrompts() {
        fetch('/get_prompts')
            .then(response => response.json())
            .then(data => {
                const assistantButtonsContainer = document.querySelector('.assistant-buttons');
                if (assistantButtonsContainer) {
                    assistantButtonsContainer.innerHTML = '';

                    for (const category in data) {
                        const buttonDiv = document.createElement('div');
                        buttonDiv.classList.add('button');
                        buttonDiv.setAttribute('data-category', category);

                        // Add emoji if available for the category
                        const categoryText = categoryEmojis[category]
                            ? `${categoryEmojis[category]} ${category}`
                            : category;

                        buttonDiv.textContent = categoryText;

                        const submenuDiv = document.createElement('div');
                        submenuDiv.classList.add('submenu');

                        for (const subcategory in data[category]) {
                            const submenuItemDiv = document.createElement('div');
                            submenuItemDiv.classList.add('submenu-item');
                            submenuItemDiv.setAttribute('data-subcategory', subcategory);

                            const subcategoryLink = document.createElement('a');
                            subcategoryLink.href = '#';
                            subcategoryLink.textContent = subcategory;

                            const subSubmenuDiv = document.createElement('div');
                            subSubmenuDiv.classList.add('sub-submenu');

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
                }
            })
            .catch(error => console.error('Error fetching prompts:', error));
    }

    function initChatFunctionality() {
        document.body.addEventListener('click', (event) => {
            if (event.target.classList.contains('button-name')) {
                event.preventDefault();

                const buttonName = event.target.getAttribute('data-button-name');
                const subcategory = event.target.closest('.submenu-item').getAttribute('data-subcategory');
                const category = event.target.closest('.button').getAttribute('data-category');

                showLoadingAnimation();

                lastMessageIndex = 0;
                clearChatWindow();

                deleteConversationAndFetchPrompt(category, subcategory, buttonName)
                    .then(conversation => {
                        displayNewMessages(conversation);
                    })
                    .catch(error => console.error('Error fetching conversation:', error))
                    .finally(() => {
                        hideLoadingAnimation();
                    });
            }
        });
    }

    function initChatForm() {
        const chatForm = document.getElementById('chat-form');
        const chatInput = document.getElementById('chat-input');

        chatForm.addEventListener('submit', function(event) {
            event.preventDefault();

            const formData = new FormData(chatForm);
            const promptInput = document.getElementById('chat-input').value;
            formData.append('prompt', promptInput);

            showLoadingAnimation();

            fetch('/send_typed_prompt_for_openai_assistant_response', {
                method: 'POST',
                body: formData,
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                if (data.error) {
                    return Promise.reject(data.error);
                }
                displayNewMessages(data.conversation);
                chatInput.value = '';
            })
            .catch(error => console.error('Error submitting message:', error))
            .finally(() => {
                hideLoadingAnimation();
            });
        });
    }

    // Function to initialize the logout button
    function initLogout() {
        const logoutLink = document.getElementById('logout-link');
        if (logoutLink) {
            logoutLink.addEventListener('click', function(event) {
                event.preventDefault();
                fetch('/logout', { method: 'GET' })
                    .then(response => {
                        if (response.redirected) {
                            window.location.href = response.url;
                        } else {
                            console.error('Logout failed');
                        }
                    })
                    .catch(error => console.error('Error logging out:', error));
            });
        }
    }

    function clearChatWindow() {
        const chatMessagesContainer = document.querySelector('.chat-messages');
        if (chatMessagesContainer) {
            chatMessagesContainer.innerHTML = '';
        }
    }

    function deleteConversationAndFetchPrompt(category, subcategory, buttonName) {
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
            return fetch(`/get_prompt_for_openai_assistant_response?category=${encodeURIComponent(category)}&subcategory=${encodeURIComponent(subcategory)}&button_name=${encodeURIComponent(buttonName)}`)
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Network response was not ok');
                    }
                    return response.json();
                })
                .then(data => {
                    if (data.error) {
                        return Promise.reject(data.error);
                    }

                    return data.conversation;
                });
        });
    }

    function displayNewMessages(conversation) {
        const chatMessagesContainer = document.querySelector('.chat-messages');

        if (!Array.isArray(conversation)) {
            console.error("Invalid conversation format received:", conversation);
            return;
        }

        chatMessagesContainer.innerHTML = ''; // Clear old messages before displaying new ones

        let firstUserMessageHidden = false;

        conversation.forEach(message => {
            let displayMessage = true;

            // Hide the first user message if not an admin
            if (message.role === 'user' && !isAdmin && !firstUserMessageHidden) {
                firstUserMessageHidden = true; // Mark the first user message as hidden
                displayMessage = false;
            }

            // Only display system messages if the user is an admin
            if (message.role === 'system' && !isAdmin) {
                displayMessage = false;
            }

            if (displayMessage) {
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

                if (Array.isArray(message.content_parts)) {
                    message.content_parts.forEach(part => {
                        const paragraph = document.createElement('div');
                        paragraph.innerHTML = part.content;
                        textDiv.appendChild(paragraph);
                    });
                }

                messageDiv.appendChild(senderDiv);
                messageDiv.appendChild(textDiv);
                chatMessagesContainer.appendChild(messageDiv);
            }
        });

        lastMessageIndex = conversation.length;
        chatMessagesContainer.scrollTop = chatMessagesContainer.scrollHeight;
    }
});
