import mongoose from "mongoose";

const connect = async () => {
    try {
        mongoose.set("StrictQuery", true);
        await mongoose.connect(
            process.env.MONGO_DB_HOST,
            { dbName: 'test_db' }
        );
        console.log("Connected to MongoDB");
    } catch (error) {
        console.error("Error connecting to MongoDB:", error);
    }
};

const disconnect = async () => {
    try {
        await mongoose.disconnect();
        console.log("Disconnected from MongoDB");
    } catch (error) {
        console.error("Error disconnecting from MongoDB:", error);
    }
}

export default {
    connect,
    disconnect,
};