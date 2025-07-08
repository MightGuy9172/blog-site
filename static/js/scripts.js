// Mobile menu toggle
const toggleBtn = document.getElementById('menu-toggle');
const navMenu = document.getElementById('navbarResponsive');

if (toggleBtn && navMenu) {
    toggleBtn.addEventListener('click', () => {
        navMenu.classList.toggle('hidden');
    });
}

// Sticky navbar behavior
let scrollPos = 0;
const mainNav = document.getElementById('mainNav');

if (mainNav) {
    const headerHeight = mainNav.clientHeight;

    window.addEventListener('scroll', () => {
        const currentTop = document.body.getBoundingClientRect().top * -1;

        if (currentTop < scrollPos) {
            // Scrolling up
            if (currentTop > 0 && mainNav.classList.contains('is-fixed')) {
                mainNav.classList.add('is-visible');
            } else {
                mainNav.classList.remove('is-visible', 'is-fixed');
            }
        } else {
            // Scrolling down
            mainNav.classList.remove('is-visible');
            if (currentTop > headerHeight && !mainNav.classList.contains('is-fixed')) {
                mainNav.classList.add('is-fixed');
            }
        }

        scrollPos = currentTop;
    });
}
