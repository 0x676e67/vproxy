use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct TTLCalculator;

impl TTLCalculator {
    pub fn ttl_boundary(&self, ttl: u64) -> u64 {
        let start = SystemTime::now();
        let timestamp = start
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(rand::random());

        let time = self.calculate_ttl_boundary(timestamp, ttl);
        fxhash::hash64(&time.to_be_bytes())
    }

    fn calculate_ttl_boundary(&self, timestamp: u64, ttl: u64) -> u64 {
        timestamp - (timestamp % ttl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_current_stable_value_with_different_ttl() {
        let calculator = TTLCalculator;

        for _ in 0..10 {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let result = calculator.ttl_boundary(2);
            println!("Result: {}", result);
        }
    }
}
