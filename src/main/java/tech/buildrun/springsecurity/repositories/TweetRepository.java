package tech.buildrun.springsecurity.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import tech.buildrun.springsecurity.models.Tweet;

public interface TweetRepository extends JpaRepository<Tweet, Long>{
}
