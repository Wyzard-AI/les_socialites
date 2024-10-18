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
                buttonDiv.textContent = category;

                const submenuDiv = document.createElement('div');
                submenuDiv.classList.add('submenu');

                // Iterate through each subcategory in the category
                for (const subcategory in data[category]) {
                    const submenuItemDiv = document.createElement('div');
                    submenuItemDiv.classList.add('submenu-item');

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
                        subSubmenuDiv.appendChild(buttonLink);
                    });

                    submenuItemDiv.appendChild(subcategoryLink);
                    submenuItemDiv.appendChild(subSubmenuDiv);
                    submenuDiv.appendChild(submenuItemDiv);
                }

                buttonDiv.appendChild(submenuDiv);
                assistantButtonsContainer.appendChild(buttonDiv);
            }

            // Add event listeners for the dynamically created buttons
            addButtonEventListeners();
        })
        .catch(error => console.error('Error fetching prompts:', error));

    // Function to add click event listeners to dynamically created buttons
    function addButtonEventListeners() {
        const buttons = document.querySelectorAll('div.button');

        buttons.forEach(button => {
            button.addEventListener('click', () => {
                // Toggle the submenu visibility when a button is clicked
                const submenu = button.querySelector('.submenu');
                if (submenu) {
                    const isVisible = submenu.style.display === 'block';
                    submenu.style.display = isVisible ? 'none' : 'block';
                }
            });
        });
    }
});
