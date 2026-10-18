//! Bounded, page-based retrieval of evidence.

use serde::Serialize;

/// Pagination request (1-based pages).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PageParams {
    /// Page number, starting at 1.
    pub page: usize,
    /// How many items per page.
    pub page_size: usize,
}

impl PageParams {
    /// Build page parameters, normalizing out-of-range values.
    pub fn new(page: usize, page_size: usize) -> Self {
        Self {
            page: page.max(1),
            page_size: page_size.max(1),
        }
    }
}

/// A page of items plus the metadata needed to request the next one.
#[derive(Debug, Clone, Serialize)]
pub struct Paged<T> {
    /// Items on this page.
    pub items: Vec<T>,
    /// 1-based page number returned.
    pub page: usize,
    /// Page size used.
    pub page_size: usize,
    /// Total items across all pages.
    pub total_items: usize,
    /// Total number of pages.
    pub total_pages: usize,
    /// True when more pages exist after this one.
    pub has_next: bool,
}

/// Slice `items` into the requested page.
pub fn paginate<T>(items: &[T], params: PageParams) -> Paged<T>
where
    T: Clone,
{
    let total_items = items.len();
    let total_pages = if total_items == 0 {
        0
    } else {
        total_items.div_ceil(params.page_size)
    };
    let start = (params.page - 1)
        .saturating_mul(params.page_size)
        .min(total_items);
    let end = start.saturating_add(params.page_size).min(total_items);
    let page_items = items[start..end].to_vec();
    let has_next = end < total_items;
    Paged {
        items: page_items,
        page: params.page,
        page_size: params.page_size,
        total_items,
        total_pages,
        has_next,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn numbers() -> Vec<u32> {
        (1..=10).collect()
    }

    #[test]
    fn first_page() {
        let page = paginate(&numbers(), PageParams::new(1, 3));
        assert_eq!(page.items, vec![1, 2, 3]);
        assert_eq!(page.total_items, 10);
        assert_eq!(page.total_pages, 4);
        assert!(page.has_next);
    }

    #[test]
    fn last_page_is_partial() {
        let page = paginate(&numbers(), PageParams::new(4, 3));
        assert_eq!(page.items, vec![10]);
        assert!(!page.has_next);
        assert_eq!(page.total_pages, 4);
    }

    #[test]
    fn beyond_the_end_is_empty() {
        let page = paginate(&numbers(), PageParams::new(9, 3));
        assert!(page.items.is_empty());
        assert!(!page.has_next);
        assert_eq!(page.total_items, 10);
    }

    #[test]
    fn empty_input_has_no_pages() {
        let page: Paged<u32> = paginate(&[], PageParams::new(1, 5));
        assert!(page.items.is_empty());
        assert_eq!(page.total_pages, 0);
        assert_eq!(page.total_items, 0);
    }

    #[test]
    fn zero_page_number_is_normalized_to_one() {
        let page = paginate(&numbers(), PageParams::new(0, 2));
        assert_eq!(page.page, 1);
        assert_eq!(page.items, vec![1, 2]);
    }
}
