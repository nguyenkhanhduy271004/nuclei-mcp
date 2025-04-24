/**
 * Nuclei MCP Scanner UI JavaScript
 */

document.addEventListener('DOMContentLoaded', function () {
    // Enable Bootstrap tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Enable Bootstrap popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Add event listener to the template filter dropdown
    const templateFilter = document.getElementById('templateFilter');
    if (templateFilter) {
        templateFilter.addEventListener('change', function () {
            filterTemplates(this.value);
        });
    }

    // Add event listener to the severity filter buttons
    const severityBtns = document.querySelectorAll('.severity-filter-btn');
    if (severityBtns.length > 0) {
        severityBtns.forEach(btn => {
            btn.addEventListener('click', function () {
                const severity = this.getAttribute('data-severity');
                filterVulnerabilitiesBySeverity(severity);
            });
        });
    }
});

/**
 * Filter templates by tag
 * @param {string} tag - The tag to filter by
 */
function filterTemplates(tag) {
    const templates = document.querySelectorAll('.template-item');
    if (tag === 'all') {
        templates.forEach(template => {
            template.style.display = 'block';
        });
    } else {
        templates.forEach(template => {
            const tags = template.getAttribute('data-tags');
            if (tags && tags.includes(tag)) {
                template.style.display = 'block';
            } else {
                template.style.display = 'none';
            }
        });
    }
}

/**
 * Filter vulnerabilities by severity
 * @param {string} severity - The severity level to filter by
 */
function filterVulnerabilitiesBySeverity(severity) {
    const vulnRows = document.querySelectorAll('.vuln-row');
    if (severity === 'all') {
        vulnRows.forEach(row => {
            row.style.display = '';
        });
    } else {
        vulnRows.forEach(row => {
            const rowSeverity = row.getAttribute('data-severity');
            if (rowSeverity === severity) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    }
} 