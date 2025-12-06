use crate::merkle_tree::Entry;
use std::error::Error;
use std::fs::File;
use std::path::Path;

pub fn parse_csv_to_entries<P: AsRef<Path>>(path: P) -> Result<Vec<Entry>, Box<dyn Error>> {
    let file = File::open(path)?;
    let mut rdr = csv::ReaderBuilder::new().from_reader(file);

    let mut entries = Vec::new();

    // Iterate over each record in the CSV file
    for result in rdr.records() {
        let record = result?;

        // Expect a single column containing the data value for each entry
        if let Some(data) = record.get(0) {
            // Create a new Entry with the data and its hashed representation
            let entry = Entry::new(data.to_string());
            entries.push(entry);
        } else {
            return Err("Missing data column in CSV".into());
        }
    }

    Ok(entries)
}