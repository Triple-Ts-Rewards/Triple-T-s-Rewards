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

function initializeStore(sponsorId, productsUrl) {
  loadProducts(sponsorId, productsUrl); 
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

async function loadProducts(sponsorId, productsUrl, query = '', minPrice = '', maxPrice = '', page = 1) {
  const container = document.getElementById('products');
  if (!container) {
    console.error("❌ No #products container found — aborting loadProducts()");
    return;
  }

  try {
    const sortBy = document.getElementById('current_sort').value;
    const limit = 20;

    // ✅ Use the passed-in productsUrl or fallback
    const baseUrl = productsUrl || document.getElementById("products_url")?.value || `/truck-rewards/products/${sponsorId}`;
    let url = `${baseUrl}?page=${page}`;

    if (query) url += `&q=${encodeURIComponent(query)}`;
    if (minPrice) url += `&min_price=${encodeURIComponent(minPrice)}`;
    if (maxPrice) url += `&max_price=${encodeURIComponent(maxPrice)}`;

    console.log("🔎 Fetching products from:", url);

    const response = await fetch(url);
    if (!response.ok) {
      const text = await response.text();
      console.error("Response not OK:", response.status, text);
      throw new Error(`Server error: ${response.status}`);
    }

    const data = await response.json();
    const products = data.products || [];
    const totalPages = data.pages || 1;
    const currentPage = data.page || 1;

    container.innerHTML = "";

    if (products.length === 0) {
      container.innerHTML = "<p>No products found in this sponsor's store.</p>";
      document.getElementById("pagination").innerHTML = "";
      return;
    }

    // ✅ Sorting logic
    switch (sortBy) {
      case 'name_asc':
        products.sort((a, b) => a.title.localeCompare(b.title));
        break;
      case 'name_desc':
        products.sort((a, b) => b.title.localeCompare(a.title));
        break;
      case 'price_asc':
        products.sort((a, b) => a.pointsEquivalent - b.pointsEquivalent);
        break;
      case 'price_desc':
        products.sort((a, b) => b.pointsEquivalent - a.pointsEquivalent);
        break;
    }

    // ✅ Render products
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
        </div>`;
      container.appendChild(card);
    });

    // ✅ Render pagination below products
    renderPagination(currentPage, totalPages, sponsorId, query, minPrice, maxPrice);

    // Smooth scroll back to top
    window.scrollTo({ top: container.offsetTop - 120, behavior: 'smooth' });

  } catch (err) {
    console.error("Error loading products:", err);
    container.innerHTML = "<p>Error loading products.</p>";
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

function renderPagination(currentPage, totalPages, sponsorId, query, minPrice, maxPrice) {
  const pagination = document.getElementById("pagination");
  pagination.innerHTML = "";

  if (totalPages <= 1) return;

  const MAX_VISIBLE_PAGES = 7; // window size

  const createButton = (label, page, disabled = false, active = false) => {
    const btn = document.createElement("button");
    btn.textContent = label;
    if (active) btn.classList.add("active");
    if (disabled) {
      btn.disabled = true;
    } else {
      btn.onclick = () => loadProducts(sponsorId, query, minPrice, maxPrice, page);
    }
    return btn;
  };

  // Previous button
  pagination.appendChild(createButton("Previous", currentPage - 1, currentPage === 1));

  // Compute visible range
  let startPage = Math.max(1, currentPage - Math.floor(MAX_VISIBLE_PAGES / 2));
  let endPage = startPage + MAX_VISIBLE_PAGES - 1;
  if (endPage > totalPages) {
    endPage = totalPages;
    startPage = Math.max(1, endPage - MAX_VISIBLE_PAGES + 1);
  }

  // If startPage > 1, show 1 and ellipsis
  if (startPage > 1) {
    pagination.appendChild(createButton("1", 1));
    if (startPage > 2) {
      const dots = document.createElement("span");
      dots.textContent = "...";
      dots.style.color = "#aaa";
      pagination.appendChild(dots);
    }
  }

  // Visible page buttons
  for (let i = startPage; i <= endPage; i++) {
    pagination.appendChild(createButton(i, i, false, i === currentPage));
  }

  // If endPage < totalPages, show ellipsis and last page
  if (endPage < totalPages) {
    if (endPage < totalPages - 1) {
      const dots = document.createElement("span");
      dots.textContent = "...";
      dots.style.color = "#aaa";
      pagination.appendChild(dots);
    }
    pagination.appendChild(createButton(totalPages, totalPages));
  }

  // Next button
  pagination.appendChild(createButton("Next", currentPage + 1, currentPage === totalPages));
}
