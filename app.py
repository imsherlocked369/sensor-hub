from functools import wraps
import hashlib
import json
import os
import secrets
from datetime import datetime
from flask import Flask, Response, request
from flask_restful import Api, Resource
from flask_caching import Cache
from flask_sqlalchemy import SQLAlchemy
from jsonschema import ValidationError, validate
from sqlalchemy.exc import IntegrityError
from sqlalchemy.engine import Engine
from sqlalchemy import event
from werkzeug.exceptions import BadRequest, Conflict, Forbidden, NotFound, UnsupportedMediaType
from werkzeug.routing import BaseConverter

JSON = "application/json"

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///test.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["CACHE_TYPE"] = "FileSystemCache"
app.config["CACHE_DIR"] = os.path.join(app.instance_path, "cache")

db = SQLAlchemy(app)
api = Api(app)
cache = Cache(app)

@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

deployments = db.Table("deployments",
    db.Column("deployment_id", db.Integer, db.ForeignKey("deployment.id"), primary_key=True),
    db.Column("sensor_id", db.Integer, db.ForeignKey("sensor.id"), primary_key=True)
)



class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    altitude = db.Column(db.Float, nullable=True)
    description=db.Column(db.String(256), nullable=True)

    sensor = db.relationship("Sensor", back_populates="location", uselist=False)

    def serialize(self, short_form=False):
        doc = {
            "name": self.name
        }
        if not short_form:
            doc["longitude"] = self.longitude
            doc["latitude"] = self.latitude
            doc["altitude"] = self.altitude
            doc["description"] = self.description
        return doc

    def deserialize(self, doc):
        self.name = doc["name"]
        self.latitude = doc.get("latitude")
        self.longitude = doc.get("longitude")
        self.altitude = doc.get("altitude")
        self.description = doc.get("description")


class Deployment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    start = db.Column(db.DateTime, nullable=False)
    end = db.Column(db.DateTime, nullable=False)
    name = db.Column(db.String(128), nullable=False)

    sensors = db.relationship("Sensor", secondary=deployments, back_populates="deployments")


class Sensor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), nullable=False, unique=True)
    model = db.Column(db.String(128), nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey("location.id"), unique=True)

    location = db.relationship("Location", back_populates="sensor")
    measurements = db.relationship("Measurement", back_populates="sensor")
    deployments = db.relationship("Deployment", secondary=deployments, back_populates="sensors")
    api_key = db.relationship("ApiKey", back_populates="sensor")

    def serialize(self):
        return {
            "name": self.name,
            "model": self.model,
            "location": self.location and self.location.name
        }

    def deserialize(self, doc):
        self.name = doc["name"]
        self.model = doc["model"]

    @staticmethod
    def json_schema():
        schema = {
            "type": "object",
            "required": ["name", "model"]
        }
        props = schema["properties"] = {}
        props["name"] = {
            "description": "Sensor's unique name",
            "type": "string"
        }
        props["model"] = {
            "description": "Name of the sensor's model",
            "type": "string"
        }
        return schema


class Measurement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sensor_id = db.Column(db.Integer, db.ForeignKey("sensor.id", ondelete="SET NULL"))
    value = db.Column(db.Float, nullable=False)
    time = db.Column(db.DateTime, nullable=False)

    sensor = db.relationship("Sensor", back_populates="measurements")

    def serialize(self):
        return {
            "time": self.time.isoformat(),
            "value": self.value
        }

    def deserialize(self, doc):
        # replace with your answer from exercise "POSTing it All Together"
        raise NotImplementedError

    @staticmethod
    def json_schema():
        # replace with your answer from exercise "POSTing it All Together"
        raise NotImplementedError


class ApiKey(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), nullable=False, unique=True)
    sensor_id = db.Column(db.Integer, db.ForeignKey("sensor.id"), nullable=True)
    admin =  db.Column(db.Boolean, default=False)

    sensor = db.relationship("Sensor", back_populates="api_key", uselist=False)

    @staticmethod
    def key_hash(key):
        return hashlib.sha256(key.encode()).hexdigest()


def require_admin(func):

    @wraps(func)
    def wrapper(*args, **kwargs):
        key_hash = ApiKey.key_hash(request.headers.get("Sensorhub-Api-Key", "").strip())
        db_key = ApiKey.query.filter_by(admin=True).first()
        if secrets.compare_digest(key_hash, db_key.key):
            return func(*args, **kwargs)
        raise Forbidden
    return wrapper

def require_sensor_key(func):

    @wraps(func)
    def wrapper(self, sensor, *args, **kwargs):
        key_hash = ApiKey.key_hash(request.headers.get("Sensorhub-Api-Key", "").strip())
        db_key = ApiKey.query.filter_by(sensor=sensor).first()
        if db_key is not None and secrets.compare_digest(key_hash, db_key.key):
            return func(*args, **kwargs)
        raise Forbidden
    return wrapper


class SensorConverter(BaseConverter):

    def to_python(self, sensor_name):
        db_sensor = Sensor.query.filter_by(name=sensor_name).first()
        if db_sensor is None:
            raise NotFound
        return db_sensor

    def to_url(self, db_sensor):
        return db_sensor.name


class SensorCollection(Resource):
    @require_admin
    def get(self):
        response_data = []
        sensors = Sensor.query.all()
        for sensor in sensors:
            response_data.append(sensor.serialize())
        return response_data

    @require_admin
    def post(self):
        if not request.json:
            raise UnsupportedMediaType

        try:
            validate(request.json, Sensor.json_schema())
        except ValidationError as e:
            raise BadRequest(description=str(e))

        sensor = Sensor()
        sensor.deserialize(request.json)
        try:
            db.session.add(sensor)
            db.session.commit()
        except IntegrityError:
            raise Conflict(
                description="Sensor with name '{name}' already exists.".format(
                    **request.json
                )
            )

        return Response(status=201, headers={
            "Location": api.url_for(SensorItem, sensor=sensor)
        })


class SensorItem(Resource):

    def get(self, sensor):
        return sensor.serialize()

    @require_admin
    def put(self, sensor):
        if not request.json:
            raise UnsupportedMediaType

        try:
            validate(request.json, Sensor.json_schema())
        except ValidationError as e:
            raise BadRequest(description=str(e))

        sensor.deserialize(request.json)
        try:
            db.session.add(sensor)
            db.session.commit()
        except IntegrityError:
            raise Conflict(
                description="Sensor with name '{name}' already exists.".format(
                    **request.json
                )
            )

        return Response(status=204)

    def delete(self, sensor):
        db.session.delete(sensor)
        db.session.commit()

        return Response(status=204)




def page_key(*args, **kwargs):
    page = request.args.get("page", 0)
    return request.path + f"[page_{page}]"

class HealthCheck(Resource):
    def get(self):
        return {"status": "ok"}, 200

class MeasurementCollection(Resource):

    PAGE_SIZE = 50

    @cache.cached(timeout=None, make_cache_key=page_key, response_filter=lambda r: False)
    def get(self, sensor):
        try:
            page = int(request.args.get("page", 0))
        except ValueError as e:
            raise BadRequest(description=str(e))

        remaining = Measurement.query.filter_by(
            sensor=sensor
        ).order_by("time").offset(page * self.PAGE_SIZE)
        body = {
            "sensor": sensor.name,
            "measurements": []
        }
        for meas in remaining.limit(self.PAGE_SIZE):
            body["measurements"].append(meas.serialize())

        response = Response(json.dumps(body), 200, mimetype=JSON)
        if len(body["measurements"]) == self.PAGE_SIZE:
            cache.set(page_key(), response, timeout=None)
        return body

    def post(self, sensor):
        # replace with your answer from exercise "POSTing it All Together"
        raise NotImplementedError


class MeasurementItem(Resource):

    def delete(self, sensor, measurement):
        pass


app.url_map.converters["sensor"] = SensorConverter

api.add_resource(SensorCollection, "/api/sensors/")
api.add_resource(HealthCheck, "/api/health/")

api.add_resource(SensorItem, "/api/sensors/<sensor:sensor>/")
api.add_resource(MeasurementCollection, "/api/sensors/<sensor:sensor>/measurements/")

with app.app_context():
    db.create_all()
    # Seed admin key if none exists
    if not ApiKey.query.filter_by(admin=True).first():
        key = "19FS6S0zdjIaPYkN9UcTy67qfbGkys7pv3SI341IHRE"
        db_key = ApiKey(
            key=ApiKey.key_hash(key),
            admin=True
        )
        db.session.add(db_key)
        db.session.commit()
        print(f"Admin key seeded: {key}")

if __name__ == "__main__":
    app.run(debug=True)

