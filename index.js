const { ApolloServer,  PubSub } = require('apollo-server');
const mongoose = require('mongoose');
const dotenv = require('dotenv');

dotenv.config();

const typeDefs = require('./graphql/typeDefs');
const resolvers = require('./graphql/resolvers');
// const { MONGODB } = require('./config');
const { MONGODB } = process.env;

const pubsub = new PubSub();

const PORT = process.env.PORT || 8900;

const server = new ApolloServer({
    typeDefs,
    resolvers,
    context: ({ req }) => ({ req, pubsub })
});

mongoose.connect(MONGODB, { useNewUrlParser: true, useUnifiedTopology: true  })
    .then(() => {
        console.log('MongoDb connected');
        return server.listen({ port: PORT });
    }).then(res => {
        console.log(`Server is running on port ${res.url}`)
    })
    .catch(err => {
        console.log(err);
    });
