package tech.buildrun.springsecurity.repositories;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import tech.buildrun.springsecurity.models.Tweet;
@Repository
public interface TweetRepository extends JpaRepository<Tweet, Long>{
}
