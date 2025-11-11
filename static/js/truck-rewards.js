function updateSortUI(currentSort) {
  const [sortBy, sortDir] = currentSort.split('_');

  document.querySelectorAll('a.sort-link').forEach(link => {
    link.classList.remove('active', 'sort-asc', 'sort-desc');
  });

  // Add active state to the correct link
  if (sortBy === 'name') {
    const link = document.getElementById('sort-name');
    link.classList.add('active');
    link.classList.add(sortDir === 'asc' ? 'sort-asc' : 'sort-desc');
  } else if (sortBy === 'price') {
    const link = document.getElementById('sort-price');
    link.classList.add('active');
    link.classList.add(sortDir === 'asc' ? 'sort-asc' : 'sort-desc');
  }
}

function initializeStore(sponsorId) {
  loadProducts(sponsorId); 
  updateSortUI(document.getElementById('current_sort').value);

  const searchForm = document.getElementById('search-form');
  if (searchForm) {
    searchForm.addEventListener('submit', (event) => {
      event.preventDefault();
      const searchInput = document.getElementById('search-input');
      const minPriceInput = document.getElementById('min-price');
      const maxPriceInput = document.getElementById('max-price');

      loadProducts(sponsorId, searchInput.value, minPriceInput.value, maxPriceInput.value);
    });
  }
}

async function loadProducts(sponsorId, query = '', minPrice = '', maxPrice = '') {
  try {

    const sortBy = document.getElementById('current_sort').value;

    let url = `/truck-rewards/products/${sponsorId}?q=${encodeURIComponent(query)}`;
    if (minPrice) url += `&min_price=${encodeURIComponent(minPrice)}`;
    if (maxPrice) url += `&max_price=${encodeURIComponent(maxPrice)}`;

    const response = await fetch(url);
    let products = await response.json(); // Changed to 'let' to allow sorting

    const container = document.getElementById("products");
    container.innerHTML = "";

    if (products.error) {
      container.innerHTML = `<p>Error loading products: ${products.error}</p>`;
      return;
    }

    if (products.length === 0) {
      container.innerHTML = "<p>No products found in this sponsor's store.</p>";
      return;
    }

    try {
        switch (sortBy) {
            case 'name_asc':
                products.sort((a, b) => {
                    return a.title.localeCompare(b.title) || (a.pointsEquivalent - b.pointsEquivalent);
                });
                break;
            case 'name_desc':
                products.sort((a, b) => {
                    return b.title.localeCompare(a.title) || (a.pointsEquivalent - b.pointsEquivalent);
                });
                break;
            case 'price_asc':
                products.sort((a, b) => {
                    return (a.pointsEquivalent - b.pointsEquivalent) || a.title.localeCompare(b.title);
                });
                break;
            case 'price_desc':
                products.sort((a, b) => {
                    return (b.pointsEquivalent - a.pointsEquivalent) || a.title.localeCompare(b.title);
                });
                break;
        }
    } catch (e) {
        console.error("Sorting error:", e);
    }

    products.forEach(p => {
      const card = document.createElement("div");
      card.className = "product-card";
      const imageUrl = p.image || 'https://i.ebayimg.com/images/g/placeholder/s-l225.jpg';

      const productData = JSON.stringify(p).replace(/'/g, "&apos;");

      card.innerHTML = `
        <img src="${imageUrl}" alt="${p.title}">
        <div class="title">${p.title}</div>
        <div class="price">$${p.price.toFixed(2)}</div>
        <div class="points">${p.pointsEquivalent} points</div>
        <div class="product-actions">
          <button class="add-to-cart-btn" data-product='${productData}'>Add to Cart</button>
          <button class="add-to-wishlist-btn" data-product='${productData}'>Add to Wishlist</button>
        </div>
      `;
      container.appendChild(card);
    });
  } catch (err) {
    console.error("Error loading products:", err);
    const container = document.getElementById("products");
    container.innerHTML = "<p>A network error occurred while trying to load products.</p>";
  }
}

async function addToCart(productData, sponsorId) {
  try {
    const csrfToken = document.querySelector('input[name="csrf_token"]').value;

    const dataToSend = { ...productData, sponsor_id: sponsorId };

    const response = await fetch('/truck-rewards/add_to_cart', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-CSRFToken': csrfToken
      },
      body: new URLSearchParams(dataToSend)
    });

    if (response.ok) {
      alert(`'${productData.title}' was added to your cart!`);
    } else {
      throw new Error('Failed to add item to cart.');
    }
  } catch (err) {
    console.error("Error adding to cart:", err);
    alert("There was an error adding the item to your cart.");
  }
}

async function addToWishlist(productData) {
  try {
    const csrfToken = document.querySelector('input[name="csrf_token"]').value;

    const response = await fetch('/truck-rewards/wishlist/add', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-CSRFToken': csrfToken
      },
      body: new URLSearchParams(productData)
    });

    const result = await response.json();
    alert(result.message);
  } catch (err) {
    console.error("Error adding to wishlist:", err);
    alert("There was an error adding the item to your wishlist.");
  }
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('a.sort-link').forEach(button => {
    button.addEventListener('click', (e) => {
      e.preventDefault();
      const sortBy = e.currentTarget.dataset.sortBy; 
      const sortInput = document.getElementById('current_sort');
      const currentSort = sortInput.value;
      let newSort;

      if (currentSort.startsWith(sortBy)) {
        newSort = currentSort.endsWith('asc') ? `${sortBy}_desc` : `${sortBy}_asc`;
      } else {
        newSort = `${sortBy}_asc`;
      }
      
      sortInput.value = newSort;
      
      updateSortUI(newSort);
      document.getElementById('search-form').dispatchEvent(new Event('submit'));
    });
  });

  document.getElementById('products').addEventListener('click', (event) => {
    if (event.target && event.target.classList.contains('add-to-cart-btn')) {
      const productData = JSON.parse(event.target.dataset.product.replace(/'/g, "'"));

      const sponsorId = document.getElementById('org_id').value;
      
      addToCart(productData, sponsorId);
  }
    if (event.target && event.target.classList.contains('add-to-wishlist-btn')) {
      const productData = JSON.parse(event.target.dataset.product.replace(/&apos;/g, "'"));
      addToWishlist(productData);
    }
  });

  const sponsorId = document.getElementById('org_id').value;
  if (sponsorId) {
    initializeStore(sponsorId);
  } else {
    console.error('Error: The store initialization function is not available or org_id is missing.');
    document.getElementById("products").innerHTML = "<p>Error: Could not identify store.</p>";
s}
});