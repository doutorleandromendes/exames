// Function to load and parse the CSV file
function loadCSV(file) {
    fetch(file) // Load the CSV file
        .then(response => response.text()) // Convert to text
        .then(data => {
            const products = parseCSV(data); // Parse the CSV text into an array of products
            displayProducts(products); // Display the products in the HTML
        })
        .catch(error => console.error('Error loading CSV file:', error));
}

// Function to parse the CSV string into a structured array
function parseCSV(csv) {
    const rows = csv.split('\n'); // Split the CSV by newlines to get each row
    const result = [];
    rows.forEach(row => {
        const columns = row.split(';'); // Split each row by semicolon
        if (columns.length === 4) { // Ensure it's a valid row
            result.push({
                title: columns[0].trim(),
                price: columns[1].trim(),
                pixPrice: columns[2].trim(),
                description: columns[3].trim(),
            });
        }
    });
    return result;
}

// Function to display the parsed products in HTML
function displayProducts(products) {
    const productListContainer = document.getElementById('product-list');

    products.forEach(product => {
        // Create product elements
        const productElement = document.createElement('div');
        productElement.classList.add('product');

        const productTitle = document.createElement('div');
        productTitle.classList.add('product-title');
        productTitle.innerText = product.title;
        productElement.appendChild(productTitle);

        const productDescription = document.createElement('div');
        productDescription.classList.add('product-description');
        productDescription.innerHTML = `${product.description} <br>
            <strong>Preço = ${product.price},00 (${product.pixPrice},00 via Pix)</strong>`;
        productElement.appendChild(productDescription);

         // Make the description togglable
        productTitle.addEventListener('click', () => {
            productDescription.style.display = productDescription.style.display === 'none' ? 'block' : 'none';
        });

        // Append product element to the list
        productListContainer.appendChild(productElement);
    });
}

// Load the CSV file when the page loads
window.onload = function() {
    loadCSV('products.csv'); // Ensure the CSV file is in the same folder as your HTML
};

// Search function (can be adapted as needed)
function searchProduct() {
  let query = document.getElementById('searchInput').value.toLowerCase();
  let products = document.querySelectorAll('.product');
  products.forEach(function(product) {
    let productName = product.querySelector('.product-title').textContent.toLowerCase();
    if (productName.includes(query)) {
      product.style.display = '';
    } else {
      product.style.display = 'none';
    }
  });
}


